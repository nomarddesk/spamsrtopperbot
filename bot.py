"""NomardDesk Subscriber Guard SaaS.

A single Telegram bot can protect multiple PUBLIC channels. Each connected channel
has its own 30-day license, monitored join events, Keep/Remove decisions and bursts.
Payments: TON or official USDT jetton on TON, MANUALLY confirmed on-chain by an
owner. Neither a screenshot nor a typed tx hash activates access automatically.

The Telegram Bot API does NOT provide a full channel member list. Only membership
updates delivered while this bot is a channel admin can be acted on.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import html
import logging
import os
import re
import secrets
import sqlite3
import time
from contextlib import suppress
from datetime import datetime, timezone
from decimal import Decimal, ROUND_UP
from pathlib import Path

import httpx
from telegram import ChatMember, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatType, ParseMode
from telegram.error import BadRequest, Forbidden, RetryAfter, TelegramError
from telegram.ext import Application, CallbackQueryHandler, ChatMemberHandler, CommandHandler, ContextTypes

logging.basicConfig(level=os.getenv('LOG_LEVEL','INFO'),
                    format='%(asctime)s %(levelname)s %(name)s: %(message)s')
LOG = logging.getLogger('guard_saas')
logging.getLogger('httpx').setLevel(logging.WARNING)

def parse_ids(raw: str) -> frozenset[int]:
    try:
        ids = frozenset(int(part.strip()) for part in raw.split(',') if part.strip())
    except ValueError as e:
        raise SystemExit('OWNER_IDS or ADMIN_ID must contain comma-separated numeric user IDs') from e
    if any(i <= 0 for i in ids):
        raise SystemExit('Owner IDs must be positive numeric Telegram user IDs')
    return ids

BOT_TOKEN = os.getenv('BOT_TOKEN','').strip()
OWNER_IDS = parse_ids(os.getenv('OWNER_IDS') or os.getenv('ADMIN_ID',''))
DB_PATH = os.getenv('DB_PATH','/data/guard_saas.db')
TON_WALLET = os.getenv('TON_WALLET','').strip()
USDT_WALLET = (os.getenv('USDT_TON_WALLET','').strip() or TON_WALLET)
USDT_MASTER = 'EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs'
PRICE_USD = Decimal('30.00')
LICENSE_DAYS = 30
BURST_LIMIT = max(2, int(os.getenv('BURST_THRESHOLD','200')))
BURST_WINDOW_S = max(60,int(os.getenv('BURST_WINDOW_MINUTES','10'))*60)
WARNING_AT = max(1,int(os.getenv('SUBSCRIBER_WARNING_AT','900')))
ALERT_DELAY = max(0.2,float(os.getenv('ALERT_DELAY_SECONDS','1.1')))
CHANNEL_RX = re.compile(r'^@[a-zA-Z0-9_]{5,32}$')
TX_RX = re.compile(r'^[a-zA-Z0-9_+\-=/]{32,120}$')


def valid_mainnet_wallet(address: str) -> bool:
    """Validate TON user-friendly mainnet address AND CRC16 checksum."""
    if len(address)!=48 or not re.fullmatch(r'[A-Za-z0-9_-]{48}',address):
        return False
    try:
        raw=base64.urlsafe_b64decode(address)
        if len(raw)!=36 or raw[0] not in (0x11, 0x51):
            return False  # reject testnet addresses
        return binascii.crc_hqx(raw[:34],0)==int.from_bytes(raw[34:36],'big')
    except (ValueError,binascii.Error):
        return False


def stamp(ts: float|None) -> str:
    if not ts: return 'none'
    return datetime.fromtimestamp(float(ts),tz=timezone.utc).strftime('%d %b %Y, %H:%M UTC')


def present(member: ChatMember) -> bool:
    return member.status in ('member','administrator','creator','owner') or (
        member.status == 'restricted' and bool(getattr(member,'is_member',False)))


def authorized_private(update: Update) -> bool:
    return bool(update.effective_chat and update.effective_chat.type == ChatType.PRIVATE
                and update.effective_user)


def is_owner(update: Update) -> bool:
    return bool(authorized_private(update) and update.effective_user.id in OWNER_IDS)


def clean_arg(s: str) -> str:
    s = s.strip()
    if s.startswith('https://t.me/'):
        s = '@'+s.split('https://t.me/',1)[1].split('?')[0].strip('/')
    return s


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        self.db = sqlite3.connect(path,timeout=20)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA busy_timeout=5000')
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS channels (
            chat_id INTEGER PRIMARY KEY, username TEXT, title TEXT NOT NULL,
            free_owner INTEGER NOT NULL DEFAULT 0,
            expires_at REAL NOT NULL DEFAULT 0, warning_sent REAL NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS managers (
            chat_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            connected_at REAL NOT NULL, PRIMARY KEY(chat_id,user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_managers_user ON managers(user_id);
        CREATE TABLE IF NOT EXISTS joins (
            id INTEGER PRIMARY KEY AUTOINCREMENT, update_id INTEGER UNIQUE NOT NULL,
            chat_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            full_name TEXT NOT NULL, username TEXT,
            joined_at REAL NOT NULL, decision TEXT NOT NULL DEFAULT 'pending',
            notified INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_joins_window ON joins(chat_id,joined_at);
        CREATE TABLE IF NOT EXISTS kept (
            chat_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            kept_at REAL NOT NULL, PRIMARY KEY(chat_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS bursts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER NOT NULL, created_at REAL NOT NULL,
            window_end REAL NOT NULL, state TEXT NOT NULL DEFAULT 'open', token TEXT
        );
        CREATE TABLE IF NOT EXISTS burst_members (
            burst_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            PRIMARY KEY(burst_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS invoices (
            id TEXT PRIMARY KEY, chat_id INTEGER NOT NULL,
            payer_id INTEGER NOT NULL, asset TEXT NOT NULL,
            amount TEXT NOT NULL, usd_price TEXT NOT NULL,
            wallet TEXT NOT NULL, memo TEXT NOT NULL UNIQUE,
            created_at REAL NOT NULL, expires_at REAL NOT NULL,
            state TEXT NOT NULL DEFAULT 'awaiting',
            tx_hash TEXT UNIQUE, submitted_at REAL, reviewed_at REAL,
            reviewed_by INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_invoice_pending ON invoices(state,created_at);
        CREATE TABLE IF NOT EXISTS license_notices (
            chat_id INTEGER NOT NULL, expiry REAL NOT NULL,
            kind TEXT NOT NULL,
            PRIMARY KEY(chat_id,expiry,kind)
        );
        ''')
        self.db.execute("UPDATE bursts SET state='open',token=NULL WHERE state='running'")
        self.db.commit()

    def close(self): self.db.close()
    def channel(self,cid:int): return self.db.execute('SELECT * FROM channels WHERE chat_id=?',(cid,)).fetchone()
    def by_username(self,uname:str):
        return self.db.execute('SELECT * FROM channels WHERE lower(username)=lower(?)',(uname,)).fetchone()
    def connect(self,chat,user:int,free:bool):
        with self.db:
            self.db.execute('''INSERT INTO channels(chat_id,username,title,free_owner,created_at)
                VALUES(?,?,?,?,?) ON CONFLICT(chat_id) DO UPDATE SET
                username=excluded.username,title=excluded.title,
                free_owner=MAX(channels.free_owner,excluded.free_owner)''',
                (chat.id, ('@'+chat.username if chat.username else str(chat.id)),
                 chat.title or 'Channel',int(free),time.time()))
            self.db.execute('INSERT OR REPLACE INTO managers VALUES(?,?,?)',(chat.id,user,time.time()))
    def active(self,cid:int)->bool:
        x=self.channel(cid)
        return bool(x and (x['free_owner'] or x['expires_at']>time.time()))
    def channels_for(self,uid:int,all_channels:bool=False):
        if all_channels: return self.db.execute('SELECT * FROM channels ORDER BY created_at DESC').fetchall()
        return self.db.execute('''SELECT c.* FROM channels c JOIN managers m
            ON m.chat_id=c.chat_id WHERE m.user_id=? ORDER BY c.created_at DESC''',(uid,)).fetchall()
    def recipients(self,cid:int)->list[int]:
        return [int(r[0]) for r in self.db.execute('SELECT user_id FROM managers WHERE chat_id=?',(cid,))]
    def grant(self,cid:int,days:int):
        now=time.time()
        with self.db:
            self.db.execute('UPDATE channels SET expires_at=? WHERE chat_id=?',
                            (max(now, float(self.channel(cid)['expires_at']))+days*86400,cid))
    def create_invoice(self,cid:int,payer:int,asset:str,amount:str,wallet:str):
        invoice_id='NG'+secrets.token_hex(5).upper()
        memo='NSG-'+secrets.token_hex(6).upper()
        now=time.time()
        with self.db:
            self.db.execute('''INSERT INTO invoices
                (id,chat_id,payer_id,asset,amount,usd_price,wallet,memo,created_at,expires_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)''',
                (invoice_id,cid,payer,asset,amount,str(PRICE_USD),wallet,memo,now,now+1200))
        return self.invoice(invoice_id)
    def invoice(self,id:str): return self.db.execute('SELECT * FROM invoices WHERE id=?',(id,)).fetchone()
    def submit_invoice(self,id:str,uid:int,txhash:str)->str:
        inv=self.invoice(id)
        if not inv or inv['payer_id']!=uid: return 'Invoice not found or it belongs to another user.'
        if inv['state']!='awaiting': return 'Invoice has already been submitted or closed.'
        if time.time()>inv['expires_at']: return 'This invoice expired; create a fresh invoice.'
        try:
            with self.db:
                self.db.execute("UPDATE invoices SET state='submitted',tx_hash=?,submitted_at=? WHERE id=?",
                                (txhash,time.time(),id))
        except sqlite3.IntegrityError:
            return 'This transaction hash has already been claimed by another invoice.'
        return 'ok'
    def approve(self,id:str,who:int)->tuple[bool,str]:
        inv=self.invoice(id)
        if not inv or inv['state']!='submitted': return False,'Invoice is not awaiting verification.'
        with self.db:
            updated=self.db.execute("UPDATE invoices SET state='approved',reviewed_at=?,reviewed_by=? WHERE id=? AND state='submitted'",
                                    (time.time(),who,id))
            if updated.rowcount!=1: return False,'Already reviewed.'
            row=self.channel(inv['chat_id'])
            end=max(time.time(),float(row['expires_at']))+LICENSE_DAYS*86400
            self.db.execute('UPDATE channels SET expires_at=? WHERE chat_id=?',(end,inv['chat_id']))
        return True,stamp(end)
    def reject(self,id:str,who:int)->bool:
        with self.db:
            return self.db.execute("UPDATE invoices SET state='rejected',reviewed_at=?,reviewed_by=? WHERE id=? AND state='submitted'",
                                   (time.time(),who,id)).rowcount==1
    def invoices_waiting(self):
        return self.db.execute("SELECT * FROM invoices WHERE state='submitted' ORDER BY submitted_at").fetchall()
    def record_join(self,update_id:int,cid:int,user,joined_at:float):
        if not self.active(cid): return None,None,0
        with self.db:
            existing=self.db.execute('SELECT 1 FROM kept WHERE chat_id=? AND user_id=?',(cid,user.id)).fetchone()
            ins=self.db.execute('''INSERT OR IGNORE INTO joins
                (update_id,chat_id,user_id,full_name,username,joined_at,decision)
                VALUES(?,?,?,?,?,?,?)''',
                (update_id,cid,user.id,user.full_name,user.username,joined_at,
                 'kept' if existing else 'pending'))
            if not ins.rowcount: return None,None,0
            jid=int(ins.lastrowid)
            count=int(self.db.execute('''SELECT COUNT(DISTINCT user_id) FROM joins
                WHERE chat_id=? AND joined_at>? AND joined_at<=?''',
                (cid,joined_at-BURST_WINDOW_S,joined_at)).fetchone()[0])
            open_batch=self.db.execute('''SELECT id FROM bursts WHERE chat_id=? AND state='open'
                AND created_at<=? AND window_end>=? ORDER BY id DESC LIMIT 1''',
                (cid,joined_at,joined_at)).fetchone()
            if open_batch:
                self.db.execute('INSERT OR IGNORE INTO burst_members VALUES(?,?)',(open_batch['id'],user.id))
                return jid,None,count
            burst_id=None
            if count>=BURST_LIMIT:
                recent=self.db.execute('SELECT created_at FROM bursts WHERE chat_id=? ORDER BY created_at DESC LIMIT 1',(cid,)).fetchone()
                if not recent or joined_at-recent['created_at']>=BURST_WINDOW_S:
                    burst_id=int(self.db.execute('INSERT INTO bursts(chat_id,created_at,window_end) VALUES(?,?,?)',
                        (cid,joined_at,joined_at+BURST_WINDOW_S)).lastrowid)
                    self.db.execute('''INSERT OR IGNORE INTO burst_members(burst_id,user_id)
                        SELECT ?,user_id FROM joins WHERE chat_id=? AND joined_at>? AND joined_at<=?''',
                        (burst_id,cid,joined_at-BURST_WINDOW_S,joined_at))
            return jid,burst_id,count
    def join(self,jid:int): return self.db.execute('SELECT * FROM joins WHERE id=?',(jid,)).fetchone()
    def pending_alerts(self,limit=15000):
        return [r[0] for r in self.db.execute('SELECT id FROM joins WHERE notified=0 ORDER BY id LIMIT ?',(limit,))]
    def alerted(self,jid:int):
        with self.db: self.db.execute('UPDATE joins SET notified=1 WHERE id=?',(jid,))
    def kept(self,cid:int,uid:int)->bool:
        return self.db.execute('SELECT 1 FROM kept WHERE chat_id=? AND user_id=?',(cid,uid)).fetchone() is not None
    def keep(self,cid:int,uid:int):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO kept VALUES(?,?,?)',(cid,uid,time.time()))
            self.db.execute("UPDATE joins SET decision='kept' WHERE chat_id=? AND user_id=? AND decision='pending'",(cid,uid))
    def unkeep(self,cid:int,uid:int):
        with self.db:
            self.db.execute('DELETE FROM kept WHERE chat_id=? AND user_id=?',(cid,uid))
            self.db.execute("UPDATE joins SET decision='pending' WHERE chat_id=? AND user_id=? AND decision='kept'",(cid,uid))
    def mark(self,cid:int,uid:int,state:str):
        assert state in ('removed','left')
        with self.db:
            self.db.execute("UPDATE joins SET decision=? WHERE chat_id=? AND user_id=? AND decision='pending'",
                            (state,cid,uid))
    def burst(self,bid:int):return self.db.execute('SELECT * FROM bursts WHERE id=?',(bid,)).fetchone()
    def burst_candidates(self,bid:int):
        return [int(r[0]) for r in self.db.execute('''SELECT bm.user_id FROM burst_members bm
            JOIN bursts b ON b.id=bm.burst_id WHERE b.id=?
            AND NOT EXISTS(SELECT 1 FROM kept k WHERE k.chat_id=b.chat_id AND k.user_id=bm.user_id)
            AND EXISTS(SELECT 1 FROM joins j WHERE j.chat_id=b.chat_id AND j.user_id=bm.user_id AND j.decision='pending')''',(bid,))]
    def burst_count(self,bid:int):
        return int(self.db.execute('SELECT COUNT(*) FROM burst_members WHERE burst_id=?',(bid,)).fetchone()[0])
    def burst_token(self,bid:int):
        token=secrets.token_hex(4)
        with self.db:
            self.db.execute("UPDATE bursts SET token=? WHERE id=? AND state='open'",(token,bid))
        return token
    def burst_cancel(self,bid:int,token:str):
        with self.db:
            return bool(self.db.execute('UPDATE bursts SET token=NULL WHERE id=? AND token=? AND state=\'open\'',(bid,token)).rowcount)
    def burst_begin(self,bid:int,token:str):
        with self.db:
            return bool(self.db.execute("UPDATE bursts SET state='running',token=NULL WHERE id=? AND state='open' AND token=?",(bid,token)).rowcount)
    def burst_done(self,bid:int):
        with self.db:self.db.execute("UPDATE bursts SET state='done' WHERE id=?",(bid,))
    def burst_reset(self,bid:int):
        with self.db:self.db.execute("UPDATE bursts SET state='open' WHERE id=?",(bid,))
    def burst_ignore(self,bid:int):
        with self.db:self.db.execute("UPDATE bursts SET state='ignored',token=NULL WHERE id=? AND state='open'",(bid,))
    def latest_joins(self,cid:int,limit=8):
        return self.db.execute('SELECT * FROM joins WHERE chat_id=? ORDER BY id DESC LIMIT ?',(cid,limit)).fetchall()
    def latest_bursts(self,cid:int,limit=5):
        return self.db.execute('SELECT * FROM bursts WHERE chat_id=? ORDER BY id DESC LIMIT ?',(cid,limit)).fetchall()
    def stats(self,cid:int):
        after=time.time()-BURST_WINDOW_S
        recent=int(self.db.execute('SELECT COUNT(DISTINCT user_id) FROM joins WHERE chat_id=? AND joined_at>?',(cid,after)).fetchone()[0])
        all_=int(self.db.execute('SELECT COUNT(*) FROM joins WHERE chat_id=?',(cid,)).fetchone()[0])
        pending=int(self.db.execute("SELECT COUNT(*) FROM joins WHERE chat_id=? AND decision='pending'",(cid,)).fetchone()[0])
        kept=int(self.db.execute('SELECT COUNT(*) FROM kept WHERE chat_id=?',(cid,)).fetchone()[0])
        return recent,all_,pending,kept
    def notice_sent(self,cid:int,expiry:float,kind:str)->bool:
        return self.db.execute('SELECT 1 FROM license_notices WHERE chat_id=? AND expiry=? AND kind=?',
                               (cid,expiry,kind)).fetchone() is not None
    def mark_notice(self,cid:int,expiry:float,kind:str):
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO license_notices VALUES(?,?,?)',(cid,expiry,kind))
    def warn_needed(self,cid:int):
        x=self.channel(cid)
        if x and time.time()-float(x['warning_sent'])>86400:
            with self.db:self.db.execute('UPDATE channels SET warning_sent=? WHERE chat_id=?',(time.time(),cid))
            return True
        return False


def db(context:ContextTypes.DEFAULT_TYPE)->Store: return context.application.bot_data['store']


def tag(channel)->str: return channel['username'] or channel['title']


def cb_buttons_join(jid:int):
    return InlineKeyboardMarkup([[
        InlineKeyboardButton('✅ Keep',callback_data=f'j:k:{jid}'),
        InlineKeyboardButton('🗑 Remove',callback_data=f'j:r:{jid}')]])


def cb_buttons_burst(bid:int):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton('🧹 Review bulk removal',callback_data=f'b:a:{bid}')],
        [InlineKeyboardButton('✅ Ignore',callback_data=f'b:i:{bid}')]])


async def send_to(bot,uid:int,**kw)->bool:
    try:
        await bot.send_message(chat_id=uid,**kw)
        return True
    except Forbidden:
        LOG.info('User %s has not started this bot / blocked it',uid)
    except TelegramError as e:
        LOG.warning('Could not notify user %s: %s',uid,e)
    return False


async def managers_now(bot,cid:int)->dict[int,object]:
    """Authoritative check; never use getChatMember because member list can be inaccessible."""
    admins=await bot.get_chat_administrators(cid)
    return {a.user.id:a for a in admins}


async def can_manage(bot,cid:int,uid:int,require_bot:bool=False)->bool:
    try:
        members=await managers_now(bot,cid)
        if uid not in members: return False
        if require_bot:
            me=await bot.get_me()
            right=members.get(me.id)
            return bool(right and (right.status in ('creator','owner') or
                                   getattr(right,'can_restrict_members',False)))
        return True
    except TelegramError as e:
        LOG.warning('Admin list lookup failed channel=%s: %s',cid,e)
        return False


async def require_manager(update:Update,context:ContextTypes.DEFAULT_TYPE,cid:int)->bool:
    if not authorized_private(update): return False
    row=db(context).channel(cid)
    if row is None or not await can_manage(context.bot,cid,update.effective_user.id):
        return False
    return True


async def get_target(context, arg:str):
    arg=clean_arg(arg)
    if not (CHANNEL_RX.fullmatch(arg) or (arg.lstrip('-').isdigit() and int(arg)<0)):
        raise ValueError('Use a public @channel_username, e.g. /connect @mychannel')
    return await context.bot.get_chat(int(arg) if arg.lstrip('-').isdigit() else arg)


async def resolve_registered(context, arg:str):
    arg=clean_arg(arg)
    row=(db(context).by_username(arg) if arg.startswith('@') else
         db(context).channel(int(arg)) if arg.lstrip('-').isdigit() else None)
    if row is None: raise ValueError('Channel not connected yet. Use /connect @channel first.')
    return row


async def check_ref(update,context,with_arg:bool=True):
    if not authorized_private(update): return None
    if with_arg and not context.args:
        await update.message.reply_text('Please specify @channel. Example: /status @mychannel')
        return None
    try: row=await resolve_registered(context,context.args[0])
    except (ValueError,TelegramError) as e:
        await update.message.reply_text(str(e));return None
    if not await require_manager(update,context,row['chat_id']):
        await update.message.reply_text('You must currently be an admin of this channel.')
        return None
    return row


async def cmd_start(update,context):
    if not authorized_private(update):return
    await update.message.reply_text(
        '🛡 NomardDesk Subscriber Guard\n\n'
        'Protect public Telegram channels without CAPTCHA. New-member alerts have '
        'Keep / Remove buttons. When 200 join within 10 minutes, review a bulk-removal batch.\n\n'
        '💳 $30 per channel for 30 days. Pay in TON or USDT on TON.\n'
        'Payment verification is reviewed on-chain by our team; submitting a hash '
        'does not automatically activate service.\n\n'
        '1) Add me as channel administrator with Ban Users permission.\n'
        '2) /connect @yourchannel\n'
        '3) /subscribe @yourchannel\n\n'
        'Commands: /channels, /status @channel, /recent @channel, /bursts @channel, '
        '/paid INVOICE_ID TX_HASH, /help')


async def cmd_help(update,context):
    await cmd_start(update,context)


async def cmd_connect(update,context):
    if not authorized_private(update):return
    if not context.args:
        await update.message.reply_text('Usage: /connect @yourpublicchannel');return
    try:
        chat=await get_target(context,context.args[0])
        if chat.type!=ChatType.CHANNEL:raise ValueError('This is not a Telegram channel.')
        admins=await managers_now(context.bot,chat.id)
        person=admins.get(update.effective_user.id)
        robot=admins.get((await context.bot.get_me()).id)
        if not person:raise ValueError('You must be a current admin of that channel.')
        if not robot:raise ValueError('Add this bot as channel administrator first.')
        if not (robot.status in ('creator','owner') or getattr(robot,'can_restrict_members',False)):
            raise ValueError('Give the bot Ban Users / Restrict Members permission.')
        free=bool(update.effective_user.id in OWNER_IDS and person.status in ('creator','owner'))
        db(context).connect(chat,update.effective_user.id,free)
        row=db(context).channel(chat.id)
        await update.message.reply_text(
            f'✅ Connected {tag(row)}.\n'
            +('Your channel has free owner access.\n' if free else
              'To activate the 30-day plan, send /subscribe '+tag(row)+'\n')+
            'The bot will start monitoring after your subscription is active. '
            'Your Telegram members join normally; no verification required.')
    except (ValueError,TelegramError) as e:
        await update.message.reply_text(f'Cannot connect: {e}')


async def cmd_privacy(update,context):
    if not authorized_private(update):return
    await update.message.reply_text(
        'Privacy: The bot receives and stores the Telegram IDs, display names, usernames, '
        'join timestamps and moderation decisions of new channel subscribers (when Telegram delivers them). '
        'It also stores channel IDs, connected managers, invoice IDs and submitted transaction hashes. '
        'The data is used to operate membership alerts, removals and subscription licensing. '
        'Records are retained in the service database until the operator deletes them. '
        'Only connected channel admins get alerts for their channel. '
        'Contact the service operator to request data deletion or assistance.')


async def cmd_support(update,context):
    if not authorized_private(update):return
    if not context.args:
        await update.message.reply_text('Usage: /support INVOICE_ID and your question. Never share wallet seed phrases.')
        return
    message=' '.join(context.args)[:1000]
    successful=0
    for owner in OWNER_IDS:
        successful+=int(await send_to(context.bot,owner,
            text=f'🆘 Support request from user {update.effective_user.id} '
                 f'(@{update.effective_user.username or "none"}):\n{message}'))
    await update.message.reply_text('Support request sent to the service owner.'
                                    if successful else 'Owner is unavailable. Try again later.')


async def cmd_channels(update,context):
    if not authorized_private(update):return
    rows=db(context).channels_for(update.effective_user.id)
    if not rows:await update.message.reply_text('No channels yet. /connect @channel');return
    lines=['🛡 Your connected channels:']
    for r in rows[:50]:
        state=('Free owner access' if r['free_owner'] else
               f'Active until {stamp(r["expires_at"])}' if db(context).active(r['chat_id']) else 'Inactive — subscribe')
        lines.append(f'\n{tag(r)} — {state}')
    await update.message.reply_text('\n'.join(lines))


async def cmd_subscribe(update,context):
    row=await check_ref(update,context)
    if row is None:return
    if row['free_owner']:
        await update.message.reply_text('✅ This channel has free owner access.');return
    if not valid_mainnet_wallet(TON_WALLET) or not valid_mainnet_wallet(USDT_WALLET):
        await update.message.reply_text('Payment wallet not set up correctly. Contact the bot owner.');return
    await update.message.reply_text(
        f'💳 30-day Guard subscription for {tag(row)}\n\n'
        'Price: $30 USD / 30 days per channel. Renewals add 30 days to existing time.\n'
        'Choose TON or official USDT on TON network.\n\n'
        'A unique payment memo will be issued. Payment is confirmed by an owner after '
        'checking the blockchain. Never send USDT using TRC20, ERC20, or BSC.',
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton('TON',callback_data=f'p:TON:{row["chat_id"]}'),
            InlineKeyboardButton('USDT (TON)',callback_data=f'p:USDT:{row["chat_id"]}')]]))


async def ton_quote()->tuple[str,str]:
    # Quote current TON/USD from CoinGecko rather than assuming a stale fixed price.
    async with httpx.AsyncClient(timeout=12) as client:
        resp=await client.get('https://api.coingecko.com/api/v3/simple/price',
                              params={'ids':'the-open-network','vs_currencies':'usd'})
        resp.raise_for_status()
        raw=resp.json().get('the-open-network',{}).get('usd')
        if raw is None:raise ValueError('No TON/USD quote returned')
        price=Decimal(str(raw))
        if not price.is_finite() or price<=Decimal('0'):raise ValueError('Invalid TON/USD quote')
        ton=(PRICE_USD/price).quantize(Decimal('0.0001'),rounding=ROUND_UP)
        return str(ton),str(price)


async def new_payment(update,context,asset:str,cid:int):
    q=update.callback_query
    if not await require_manager(update,context,cid):
        await q.answer('You are not a current channel admin',show_alert=True);return
    store=db(context)
    row=store.channel(cid)
    if row['free_owner']:
        await q.answer('This channel already has free owner access',show_alert=True);return
    wallet=TON_WALLET if asset=='TON' else USDT_WALLET
    if not valid_mainnet_wallet(wallet):
        await q.answer('Payment wallet not configured',show_alert=True);return
    await q.answer('Preparing invoice')
    if asset=='TON':
        try: amount,rate=await ton_quote()
        except (httpx.HTTPError,ValueError,ArithmeticError) as e:
            LOG.warning('TON quote unavailable: %s',e)
            await q.message.reply_text('Live TON/USD price temporarily unavailable. Try again or choose USDT on TON.');return
        label=f'{amount} TON (quoted at ${rate} per TON)'
    else:
        amount='30.00'
        label='30.00 USDT on TON network'
    invoice=store.create_invoice(cid,update.effective_user.id,asset,amount,wallet)
    await q.message.reply_text(
        f'🧾 Invoice <code>{invoice["id"]}</code>\n'
        f'Channel: {html.escape(tag(row))}\n'
        f'Pay exactly: <b>{html.escape(label)}</b>\n'
        f'Send to TON address: <code>{html.escape(wallet)}</code>\n'
        f'Payment comment/memo: <code>{invoice["memo"]}</code>\n'
        f'Quote expires: {stamp(invoice["expires_at"])}\n\n'
        '⚠️ USDT must be official Tether USDT jetton on TON, not another network.\n'
        'If your wallet allows a comment, include the exact memo.\n'
        'After sending, submit your blockchain transaction hash using:\n'
        f'<code>/paid {invoice["id"]} YOUR_TRANSACTION_HASH</code>\n\n'
        'The owner will verify the transfer on-chain (recipient, amount, asset, memo if present, '
        'confirmation and unused hash). Do not rely on screenshots.',
        parse_mode=ParseMode.HTML)


async def cmd_paid(update,context):
    if not authorized_private(update):return
    if len(context.args)!=2:
        await update.message.reply_text('Usage: /paid INVOICE_ID TRANSACTION_HASH');return
    invoice_id,tx=context.args
    if not TX_RX.fullmatch(tx):
        await update.message.reply_text('Transaction hash format looks incorrect. Paste the chain transaction hash.');return
    inv=db(context).invoice(invoice_id)
    if not inv or not await require_manager(update,context,inv['chat_id']):
        await update.message.reply_text('Invoice not found or you cannot manage this channel.');return
    result=db(context).submit_invoice(invoice_id,update.effective_user.id,tx)
    if result!='ok':
        await update.message.reply_text(result);return
    await update.message.reply_text('✅ Submitted for on-chain verification. This does NOT activate your plan yet. You will get a message after review.')
    channel=db(context).channel(inv['chat_id'])
    msg=(f'💰 PAYMENT REVIEW REQUEST\n\nChannel: {tag(channel)}\n'
         f'Invoice: {invoice_id}\nPayer: {update.effective_user.id}\n'
         f'Expected: {inv["amount"]} {inv["asset"]} on TON\n'
         f'Recipient: {inv["wallet"]}\nMemo: {inv["memo"]}\n'
         f'Tx hash: {tx}\n\n'
         'IMPORTANT: Independently verify transaction on TON blockchain, '
         'recipient, asset, amount, confirmations, memo (if sent), and whether hash was used before approval. '
         'The bot does NOT auto-check transfers.')
    for oid in OWNER_IDS:
        await send_to(context.bot,oid,text=msg,
                      reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('🔎 Review invoice',callback_data=f'i:r:{invoice_id}')]]))


async def owner_review(q,context,invoice_id:str):
    inv=db(context).invoice(invoice_id)
    if not inv or inv['state']!='submitted':
        await q.answer('No submitted invoice',show_alert=True);return
    await q.answer()
    await q.message.reply_text(
        f'⚠️ Confirm manual blockchain verification for invoice {invoice_id}\n'
        f'Transfer: {inv["tx_hash"]}\nExpected: {inv["amount"]} {inv["asset"]}\n'
        f'Recipient: {inv["wallet"]}\nMemo: {inv["memo"]}\n'
        'Approve ONLY if you personally checked the real blockchain transaction '
        'and it is final, inbound to your wallet, correct asset/amount and not reused.',
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton('✅ I VERIFIED — Activate 30 days',callback_data=f'i:a:{invoice_id}')],
            [InlineKeyboardButton('❌ Reject',callback_data=f'i:x:{invoice_id}')]]))


async def cmd_pending(update,context):
    if not is_owner(update):return
    waiting=db(context).invoices_waiting()
    if not waiting:
        await update.message.reply_text('No payment submissions awaiting manual review.');return
    for inv in waiting[:20]:
        await update.message.reply_text(
            f'Invoice {inv["id"]}: {inv["amount"]} {inv["asset"]}, channel {inv["chat_id"]}\nTx {inv["tx_hash"]}',
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton('Review',callback_data=f'i:r:{inv["id"]}')]]))


async def cmd_grant(update,context):
    if not is_owner(update):return
    if len(context.args)!=2 or not context.args[1].isdigit() or not (1<=int(context.args[1])<=365):
        await update.message.reply_text('Usage: /grant @channel DAYS (1-365)');return
    try:
        row=await resolve_registered(context,context.args[0])
    except ValueError as e:
        await update.message.reply_text(str(e));return
    db(context).grant(row['chat_id'],int(context.args[1]))
    await update.message.reply_text(f'✅ {tag(row)} active through {stamp(db(context).channel(row["chat_id"])["expires_at"])}')
    for uid in db(context).recipients(row['chat_id']):
        await send_to(context.bot,uid,text=f'✅ Your channel {tag(row)} is now active through {stamp(db(context).channel(row["chat_id"])["expires_at"])}.')


async def cmd_clients(update,context):
    if not is_owner(update):return
    rows=db(context).channels_for(0,all_channels=True)
    if not rows:await update.message.reply_text('No clients yet.');return
    lines=['🛡 Managed channels:']
    for r in rows[:60]:
        state='FREE' if r['free_owner'] else ('ACTIVE' if db(context).active(r['chat_id']) else 'EXPIRED')
        lines.append(f'{tag(r)} — {state} — {stamp(r["expires_at"])}')
    await update.message.reply_text('\n'.join(lines))


async def cmd_status(update,context):
    row=await check_ref(update,context)
    if row is None:return
    recent,all_,pending,kept=db(context).stats(row['chat_id'])
    try: live=await context.bot.get_chat_member_count(row['chat_id'])
    except TelegramError:live='unavailable'
    state='Free owner access' if row['free_owner'] else (
        'Active through '+stamp(row['expires_at']) if db(context).active(row['chat_id']) else 'INACTIVE — renew')
    await update.message.reply_text(
        f'🛡 {tag(row)}\nLicense: {state}\nTelegram subscriber count: {live}\n'
        f'Joins in last {BURST_WINDOW_S//60} minutes: {recent}\n'
        f'Events observed: {all_}\nPending: {pending}\nKeep protected: {kept}\n'
        f'Burst threshold: {BURST_LIMIT} / {BURST_WINDOW_S//60} min\n\n'
        'This bot cannot enumerate people who joined before installation. '
        'It only processes delivered membership updates; it cannot guarantee a channel stays below 1,000 subscribers.')


async def cmd_recent(update,context):
    row=await check_ref(update,context)
    if row is None:return
    for j in db(context).latest_joins(row['chat_id']):
        await update.message.reply_text(
            f'{j["full_name"]} — {j["user_id"]} ({j["decision"]})',
            reply_markup=cb_buttons_join(j['id']) if j['decision']=='pending' else None)


async def cmd_bursts(update,context):
    row=await check_ref(update,context)
    if row is None:return
    batches=db(context).latest_bursts(row['chat_id'])
    if not batches:
        await update.message.reply_text('No mass-join batches yet.');return
    for b in batches:
        await update.message.reply_text(
            f'🚨 {tag(row)} batch #{b["id"]} — {b["state"]}\n'
            f'Tracked: {db(context).burst_count(b["id"])}; eligible: {len(db(context).burst_candidates(b["id"]))}',
            reply_markup=cb_buttons_burst(b['id']) if b['state']=='open' else None)


async def cmd_unkeep(update,context):
    row=await check_ref(update,context)
    if row is None:return
    if len(context.args)<2 or not context.args[1].isdigit():
        await update.message.reply_text('Usage: /unkeep @channel USER_ID');return
    db(context).unkeep(row['chat_id'],int(context.args[1]))
    await update.message.reply_text('User no longer protected by Keep.')


async def cmd_unban(update,context):
    row=await check_ref(update,context)
    if row is None:return
    if len(context.args)<2 or not context.args[1].isdigit():
        await update.message.reply_text('Usage: /unban @channel USER_ID');return
    try:
        await context.bot.unban_chat_member(row['chat_id'],int(context.args[1]),only_if_banned=True)
        await update.message.reply_text('Unbanned. Telegram does not automatically rejoin that account.')
    except TelegramError as e:
        await update.message.reply_text(f'Could not unban: {e}')


# Short cache avoids a Telegram admin-list request for every new subscriber.
# Revoked admins stop receiving notifications within 60 seconds (or at next refresh).
_ADMIN_CACHE:dict[int,tuple[float,set[int]]]={}

async def notify_channel(bot,store:Store,cid:int,**kwargs)->int:
    cached=_ADMIN_CACHE.get(cid)
    if cached and cached[0]>time.time():
        current_admins=cached[1]
    else:
        try:
            current_admins=set((await managers_now(bot,cid)).keys())
            _ADMIN_CACHE[cid]=(time.time()+60,current_admins)
        except TelegramError as e:
            LOG.warning('Cannot confirm current admins before channel notification (%s): %s',cid,e)
            return 0
    successes=0
    for uid in store.recipients(cid):
        if uid in current_admins and await send_to(bot,uid,**kwargs):
            successes+=1
    return successes


async def send_join_alert(bot,store:Store,entry):
    channel=store.channel(entry['chat_id'])
    text=(f'👤 <b>New subscriber — {html.escape(tag(channel))}</b>\n\n'
          f'Name: {html.escape(entry["full_name"][:150])}\n'
          f'Username: {"@"+html.escape(entry["username"]) if entry["username"] else "None"}\n'
          f'User ID: <code>{entry["user_id"]}</code>\n'
          f'Joined: {stamp(entry["joined_at"])}\n\n'
          'Keep protects against bulk removal; Remove bans this user from the channel.')
    return await notify_channel(bot,store,entry['chat_id'],text=text,
            parse_mode=ParseMode.HTML,reply_markup=cb_buttons_join(entry['id']))


async def join_worker(app:Application):
    queue:asyncio.Queue=app.bot_data['queue']
    store:Store=app.bot_data['store']
    while True:
        jid=await queue.get()
        try:
            event=store.join(jid)
            if event and not event['notified'] and store.active(event['chat_id']):
                if event['decision'] not in ('removed','left'):
                    sent=await send_join_alert(app.bot,store,event)
                    if not sent:
                        # Do not trap the worker infinitely if clients haven't opened the bot.
                        LOG.warning('No reachable managers for join event %s; requeue on restart',jid)
                        continue
                store.alerted(jid)
        except RetryAfter as e:
            await asyncio.sleep(float(e.retry_after)+1)
            await queue.put(jid)
        except TelegramError as e:
            LOG.warning('Telegram notification failed join %s: %s',jid,e)
            await asyncio.sleep(3)
            await queue.put(jid)
        except Exception:
            LOG.exception('Unexpected join alert error')
        finally:
            queue.task_done()
            await asyncio.sleep(ALERT_DELAY)


async def member_change(update,context):
    change=update.chat_member
    if not change:return
    cid=change.chat.id
    store=db(context)
    if not store.active(cid):return
    user=change.new_chat_member.user
    old,new=present(change.old_chat_member),present(change.new_chat_member)
    if not old and new:
        if change.new_chat_member.status in ('creator','administrator','owner'):return
        jid,bid,count=store.record_join(update.update_id,cid,user,change.date.timestamp())
        if jid is None:return
        try:context.application.bot_data['queue'].put_nowait(jid)
        except asyncio.QueueFull:LOG.warning('Queue full; join event saved in DB')
        if bid:
            channel=store.channel(cid)
            await notify_channel(context.bot,store,cid,
                text=(f'🚨 Mass-join alert for {tag(channel)}\n\n'
                      f'{count} distinct join events detected within {BURST_WINDOW_S//60} minutes.\n'
                      f'Tracked in batch #{bid}: {store.burst_count(bid)}.\n'
                      'A spike is not proof users are fake. Review before removing.'),
                reply_markup=cb_buttons_burst(bid))
        # Rate-limit count check to once every 20 joins, plus at first join.
        if count==1 or count%20==0:
            try:
                subscriber_count=await context.bot.get_chat_member_count(cid)
                if subscriber_count>=WARNING_AT and store.warn_needed(cid):
                    await notify_channel(context.bot,store,cid,
                        text=f'⚠️ {tag(store.channel(cid))} now has {subscriber_count} subscribers. '
                             'Review unexpected growth. Bot cannot enforce an exact subscriber ceiling.')
            except TelegramError as e:LOG.info('Cannot check subscriber count for %s: %s',cid,e)
    elif old and not new:
        store.mark(cid,user.id,'left')


async def remove_user(bot,store:Store,cid:int,uid:int,known_admins:set[int]|None=None)->str:
    if store.kept(cid,uid):return 'protected'
    try:
        admins=known_admins if known_admins is not None else set((await managers_now(bot,cid)).keys())
        if uid in admins:return 'admin'
    except TelegramError as e:
        LOG.warning('Admin list inaccessible, refusing removal: %s',e)
        return 'failed'
    try:
        try:
            member=await bot.get_chat_member(cid,uid)
            if not present(member):
                store.mark(cid,uid,'left')
                return 'already_left'
        except BadRequest as e:
            if 'member list is inaccessible' not in str(e).lower():raise
        await bot.ban_chat_member(cid,uid)
        store.mark(cid,uid,'removed')
        return 'removed'
    except RetryAfter:
        raise
    except TelegramError as e:
        LOG.warning('Removal failed channel=%s uid=%s: %s',cid,uid,e)
        return 'failed'


async def remove_with_retry(bot,store:Store,cid:int,uid:int,admins:set[int]|None=None):
    for _ in range(4):
        try:return await remove_user(bot,store,cid,uid,admins)
        except RetryAfter as e:await asyncio.sleep(float(e.retry_after)+1)
    return 'failed'


async def bulk_worker(app:Application,bid:int,msg_chat:int,msg_id:int):
    store:Store=app.bot_data['store']
    b=store.burst(bid)
    if not b:return
    cid=b['chat_id']
    counts={k:0 for k in ('removed','protected','admin','already_left','failed')}
    try:
        admins=set((await managers_now(app.bot,cid)).keys())
        ids=store.burst_candidates(bid)
        for i,uid in enumerate(ids,1):
            if not store.active(cid):
                store.burst_reset(bid)
                await app.bot.send_message(msg_chat,'Subscription expired during bulk removal; job stopped.')
                return
            out=await remove_with_retry(app.bot,store,cid,uid,admins)
            counts[out]+=1
            if i%25==0 or i==len(ids):
                with suppress(TelegramError):
                    await app.bot.edit_message_text(chat_id=msg_chat,message_id=msg_id,
                        text=f'🧹 Processing {i}/{len(ids)}\nRemoved: {counts["removed"]}\nFailed: {counts["failed"]}')
            await asyncio.sleep(0.35)
        store.burst_done(bid)
        with suppress(TelegramError):
            await app.bot.edit_message_text(chat_id=msg_chat,message_id=msg_id,
                text=f'✅ Batch #{bid} done. Removed: {counts["removed"]}; protected/admin: '
                     f'{counts["protected"]+counts["admin"]}; already left: {counts["already_left"]}; failed: {counts["failed"]}.')
    except Exception as e:
        LOG.exception('Bulk batch %s failed',bid)
        store.burst_reset(bid)
        await send_to(app.bot,msg_chat,text=f'⚠️ Batch #{bid} failed: {str(e)[:160]}. /bursts to retry.')


async def callbacks(update,context):
    q=update.callback_query
    if not q or not authorized_private(update):return
    data=q.data or ''
    parts=data.split(':')
    store=db(context)
    if len(parts)==3 and parts[0]=='p' and parts[1] in ('TON','USDT'):
        try:cid=int(parts[2])
        except ValueError:await q.answer('Invalid channel');return
        await new_payment(update,context,parts[1],cid);return
    if len(parts)==3 and parts[0]=='i':
        if not is_owner(update):
            await q.answer('Owner only',show_alert=True);return
        action,invoice_id=parts[1:]
        if action=='r':
            await owner_review(q,context,invoice_id);return
        inv=store.invoice(invoice_id)
        if not inv or inv['state']!='submitted':
            await q.answer('Invoice already closed',show_alert=True);return
        if action=='a':
            ok,reason=store.approve(invoice_id,update.effective_user.id)
            await q.answer('Activated' if ok else reason,show_alert=not ok)
            if ok:
                await q.edit_message_reply_markup(reply_markup=None)
                await q.message.reply_text(f'✅ Approved {invoice_id}. Active through {reason}.')
                for u in store.recipients(inv['chat_id']):
                    await send_to(context.bot,u,text=f'✅ Payment verified. {tag(store.channel(inv["chat_id"]))} active through {reason}.')
            return
        if action=='x':
            store.reject(invoice_id,update.effective_user.id)
            await q.answer('Rejected')
            await q.edit_message_reply_markup(reply_markup=None)
            await send_to(context.bot,inv['payer_id'],
                text=f'❌ Invoice {invoice_id} was not approved. Contact support with the real chain transaction details.')
            return
    if len(parts)<3:return
    if parts[0]=='j' and parts[1] in ('k','r'):
        try:jid=int(parts[2])
        except ValueError:await q.answer('Invalid join');return
        item=store.join(jid)
        if not item:await q.answer('Join not found');return
        cid=item['chat_id']
        if not await can_manage(context.bot,cid,update.effective_user.id):
            await q.answer('Not a channel admin',show_alert=True);return
        if not store.active(cid):
            await q.answer('Subscription inactive; renew first',show_alert=True);return
        if parts[1]=='k':
            if item['decision']=='removed':
                await q.answer('Already removed; unban manually',show_alert=True);return
            store.keep(cid,item['user_id'])
            await q.answer('Protected from bulk removal')
            with suppress(TelegramError):await q.edit_message_reply_markup(reply_markup=None)
            await q.message.reply_text(f'✅ Kept {item["full_name"]} ({item["user_id"]}).')
        else:
            if store.kept(cid,item['user_id']):
                await q.answer('Kept — /unkeep first',show_alert=True);return
            if item['decision']=='removed':
                await q.answer('Already removed',show_alert=True);return
            await q.answer('Removing subscriber')
            result=await remove_with_retry(context.bot,store,cid,item['user_id'])
            if result=='removed':
                with suppress(TelegramError):await q.edit_message_reply_markup(reply_markup=None)
            await q.message.reply_text(f'User {item["user_id"]}: {result}.')
        return
    if parts[0]=='b' and parts[1] in ('a','i','g','c'):
        try:bid=int(parts[2])
        except ValueError:await q.answer('Invalid batch');return
        b=store.burst(bid)
        if not b:await q.answer('Batch missing');return
        cid=b['chat_id']
        if not await can_manage(context.bot,cid,update.effective_user.id):
            await q.answer('Not a channel admin',show_alert=True);return
        if not store.active(cid):
            await q.answer('Subscription inactive; renew first',show_alert=True);return
        if b['state']!='open':await q.answer('Batch already closed',show_alert=True);return
        act=parts[1]
        if act=='i':
            store.burst_ignore(bid)
            await q.answer('Ignored')
            with suppress(TelegramError):await q.edit_message_reply_markup(reply_markup=None)
            return
        if act=='a':
            token=store.burst_token(bid)
            await q.answer()
            await q.message.reply_text(
                f'⚠️ Confirm bulk ban for {tag(store.channel(cid))}\n'
                f'Batch #{bid}: {store.burst_count(bid)} joins; '
                f'{len(store.burst_candidates(bid))} eligible.\n'
                'Keep-protected users and channel admins are excluded.\n'
                'Review carefully: a burst is not proof of fake accounts.',
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton('🗑 CONFIRM BAN',callback_data=f'b:g:{bid}:{token}'),
                    InlineKeyboardButton('Cancel',callback_data=f'b:c:{bid}:{token}')]]))
            return
        if act in ('g','c') and len(parts)==4:
            token=parts[3]
            if act=='c':
                ok=store.burst_cancel(bid,token)
                await q.answer('Cancelled' if ok else 'Expired')
                if ok:await q.edit_message_text('Bulk removal cancelled. No action taken.')
                return
            if not store.burst_begin(bid,token):
                await q.answer('Expired or already started');return
            await q.answer('Starting bulk removal')
            await q.edit_message_text(f'🧹 Processing batch #{bid}...')
            context.application.create_task(bulk_worker(context.application,bid,
                                       q.message.chat_id,q.message.message_id),update=update)
            return
    await q.answer('Invalid or expired action')


async def subscription_watcher(app:Application):
    store:Store=app.bot_data['store']
    while True:
        try:
            now=time.time()
            for ch in store.channels_for(0,True):
                if ch['free_owner'] or not ch['expires_at']:
                    continue
                left=float(ch['expires_at'])-now
                kind=None
                if left<=0:kind='expired'
                elif left<=3*86400:kind='3d'
                if kind is None or store.notice_sent(ch['chat_id'],float(ch['expires_at']),kind):
                    continue
                txt=(f'⌛ {tag(ch)} subscription has expired. Monitoring is paused. '
                     f'Use /subscribe {tag(ch)} to renew for $30 / 30 days.'
                     if kind=='expired' else
                     f'⏳ {tag(ch)} subscription expires on {stamp(ch["expires_at"])}. '
                     f'Use /subscribe {tag(ch)} to renew before monitoring stops.')
                sent=await notify_channel(app.bot,store,ch['chat_id'],text=txt)
                if sent:store.mark_notice(ch['chat_id'],float(ch['expires_at']),kind)
        except Exception:
            LOG.exception('License notification task failed')
        await asyncio.sleep(3600)


async def post_init(app):
    store:Store=app.bot_data['store']
    q:asyncio.Queue=asyncio.Queue(maxsize=20000)
    app.bot_data['queue']=q
    for jid in store.pending_alerts():
        event=store.join(jid)
        if event and store.active(event['chat_id']):
            with suppress(asyncio.QueueFull):q.put_nowait(jid)
    app.bot_data['worker']=asyncio.create_task(join_worker(app))
    app.bot_data['license_worker']=asyncio.create_task(subscription_watcher(app))
    LOG.info('Subscriber Guard SaaS online, channels=%d, queued=%d',
             len(store.channels_for(0,True)),q.qsize())
    for owner in OWNER_IDS:
        await send_to(app.bot,owner,text='🛡 Guard SaaS is online. /clients /pending /help')


async def post_shutdown(app):
    worker=app.bot_data.get('worker')
    if worker:
        worker.cancel()
        with suppress(asyncio.CancelledError):await worker
    license_worker=app.bot_data.get('license_worker')
    if license_worker:
        license_worker.cancel()
        with suppress(asyncio.CancelledError):await license_worker
    app.bot_data['store'].close()


def main():
    if not BOT_TOKEN or not OWNER_IDS:
        raise SystemExit('Set BOT_TOKEN and OWNER_IDS (or existing ADMIN_ID) in Railway')
    store=Store(DB_PATH)
    app=(Application.builder().token(BOT_TOKEN).post_init(post_init)
         .post_shutdown(post_shutdown).build())
    app.bot_data['store']=store
    app.add_handler(ChatMemberHandler(member_change,ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(CallbackQueryHandler(callbacks))
    handlers={
        'start':cmd_start,'help':cmd_help,'privacy':cmd_privacy,'support':cmd_support,
        'connect':cmd_connect,'channels':cmd_channels,
        'subscribe':cmd_subscribe,'paid':cmd_paid,'pending':cmd_pending,
        'grant':cmd_grant,'clients':cmd_clients,'status':cmd_status,
        'recent':cmd_recent,'bursts':cmd_bursts,'unkeep':cmd_unkeep,'unban':cmd_unban,
    }
    for command,fn in handlers.items():app.add_handler(CommandHandler(command,fn))
    app.run_polling(allowed_updates=['chat_member','message','callback_query'],
                    drop_pending_updates=False)

if __name__=='__main__':main()
