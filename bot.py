"""Telegram public-channel subscriber guard.

Watches Telegram's chat_member updates for a single public channel and sends
admin-only Keep / Remove controls. Detects >= BURST_THRESHOLD distinct new
members over a rolling BURST_WINDOW_MINUTES and offers confirmed bulk removal.

Telegram must actually deliver a chat_member update containing the user ID.
This bot cannot enumerate all subscribers or guarantee a membership ceiling.
"""

from __future__ import annotations

import asyncio
import html
import logging
import os
import secrets
import sqlite3
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path

from telegram import ChatMember, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatType, ParseMode
from telegram.error import BadRequest, Forbidden, RetryAfter, TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
)

LOG = logging.getLogger("subscriber_guard")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)


def positive_int(key: str, default: int) -> int:
    value = int(os.getenv(key, str(default)))
    if value < 1:
        raise ValueError(f"{key} must be positive")
    return value


TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))
CHANNEL = os.getenv("CHANNEL_USERNAME", "@massageservice0001").strip()
DB_PATH = os.getenv("DB_PATH", "./guard.db")
BURST_THRESHOLD = positive_int("BURST_THRESHOLD", 200)
BURST_WINDOW_SECONDS = positive_int("BURST_WINDOW_MINUTES", 10) * 60
ALERT_DELAY_SECONDS = max(1.2, float(os.getenv("ALERT_DELAY_SECONDS", "1.2")))


class Store:
    """Single-process SQLite state; keep the bot at one instance."""

    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS joins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                update_id INTEGER NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                display_name TEXT NOT NULL,
                username TEXT,
                joined_at REAL NOT NULL,
                decision TEXT NOT NULL DEFAULT 'pending',
                notified INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_joins_joined_at ON joins(joined_at);
            CREATE INDEX IF NOT EXISTS idx_joins_user_id ON joins(user_id);
            CREATE TABLE IF NOT EXISTS kept (
                user_id INTEGER PRIMARY KEY,
                kept_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bursts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                window_start REAL NOT NULL,
                window_end REAL NOT NULL,
                state TEXT NOT NULL DEFAULT 'open',
                confirm_token TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_bursts_created_at ON bursts(created_at);
            CREATE TABLE IF NOT EXISTS burst_members (
                burst_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (burst_id, user_id)
            );
            """
        )
        # If a restart interrupts removal, let admin retry via /bursts.
        self.conn.execute("UPDATE bursts SET state='open', confirm_token=NULL WHERE state='running'")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def record_join(
        self, update_id: int, user_id: int, display_name: str,
        username: str | None, joined_at: float,
    ) -> tuple[int | None, int | None, int]:
        """Returns (join event id, new burst id or None, recent unique count)."""
        with self.conn:
            insert = self.conn.execute(
                "INSERT OR IGNORE INTO joins "
                "(update_id,user_id,display_name,username,joined_at,decision) "
                "VALUES (?,?,?,?,?,?)",
                (update_id, user_id, display_name, username, joined_at,
                 "kept" if self.is_kept(user_id) else "pending"),
            )
            if not insert.rowcount:
                return None, None, 0
            join_id = int(insert.lastrowid)
            start = joined_at - BURST_WINDOW_SECONDS
            count = int(self.conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM joins WHERE joined_at > ? AND joined_at <= ?",
                (start, joined_at),
            ).fetchone()[0])

            # A burst collects people observed for ten minutes after triggering.
            current = self.conn.execute(
                "SELECT id FROM bursts WHERE state='open' AND created_at <= ? "
                "AND window_end >= ? ORDER BY id DESC LIMIT 1",
                (joined_at, joined_at),
            ).fetchone()
            if current:
                self.conn.execute(
                    "INSERT OR IGNORE INTO burst_members(burst_id,user_id) VALUES (?,?)",
                    (current["id"], user_id),
                )
                return join_id, None, count

            new_burst_id = None
            if count >= BURST_THRESHOLD:
                # Avoid duplicate alerts from overlapping rolling windows.
                latest = self.conn.execute(
                    "SELECT created_at FROM bursts WHERE created_at <= ? "
                    "ORDER BY created_at DESC LIMIT 1", (joined_at,),
                ).fetchone()
                if latest is None or joined_at - latest["created_at"] >= BURST_WINDOW_SECONDS:
                    new_burst_id = int(self.conn.execute(
                        "INSERT INTO bursts(created_at,window_start,window_end) VALUES (?,?,?)",
                        (joined_at, start, joined_at + BURST_WINDOW_SECONDS),
                    ).lastrowid)
                    self.conn.execute(
                        "INSERT OR IGNORE INTO burst_members(burst_id,user_id) "
                        "SELECT ?,user_id FROM joins WHERE joined_at > ? AND joined_at <= ?",
                        (new_burst_id, start, joined_at),
                    )
            return join_id, new_burst_id, count

    def join(self, join_id: int):
        return self.conn.execute("SELECT * FROM joins WHERE id=?", (join_id,)).fetchone()

    def pending_alerts(self, limit: int = 10000) -> list[int]:
        return [r[0] for r in self.conn.execute(
            "SELECT id FROM joins WHERE notified=0 ORDER BY id LIMIT ?", (limit,)
        ).fetchall()]

    def mark_alerted(self, join_id: int) -> None:
        with self.conn:
            self.conn.execute("UPDATE joins SET notified=1 WHERE id=?", (join_id,))

    def is_kept(self, user_id: int) -> bool:
        return self.conn.execute("SELECT 1 FROM kept WHERE user_id=?", (user_id,)).fetchone() is not None

    def keep(self, user_id: int) -> None:
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO kept(user_id,kept_at) VALUES (?,?)", (user_id,time.time()))
            self.conn.execute("UPDATE joins SET decision='kept' WHERE user_id=? AND decision='pending'", (user_id,))

    def unkeep(self, user_id: int) -> bool:
        with self.conn:
            result = self.conn.execute("DELETE FROM kept WHERE user_id=?", (user_id,))
            self.conn.execute("UPDATE joins SET decision='pending' WHERE user_id=? AND decision='kept'", (user_id,))
            return result.rowcount > 0

    def set_user_decision(self, user_id: int, decision: str) -> None:
        assert decision in ("removed", "left")
        with self.conn:
            self.conn.execute(
                "UPDATE joins SET decision=? WHERE user_id=? AND decision NOT IN ('removed','kept')",
                (decision, user_id),
            )

    def burst(self, burst_id: int):
        return self.conn.execute("SELECT * FROM bursts WHERE id=?", (burst_id,)).fetchone()

    def burst_stats(self, burst_id: int) -> tuple[int, int]:
        total = int(self.conn.execute(
            "SELECT COUNT(*) FROM burst_members WHERE burst_id=?", (burst_id,)
        ).fetchone()[0])
        eligible = len(self.burst_candidates(burst_id))
        return total, eligible

    def burst_candidates(self, burst_id: int) -> list[int]:
        # Only current *unreviewed* join events. Kept IDs are excluded.
        rows = self.conn.execute(
            """
            SELECT bm.user_id FROM burst_members bm
            WHERE bm.burst_id=?
              AND NOT EXISTS (SELECT 1 FROM kept k WHERE k.user_id=bm.user_id)
              AND EXISTS (SELECT 1 FROM joins j WHERE j.user_id=bm.user_id AND j.decision='pending')
            ORDER BY bm.user_id
            """,
            (burst_id,),
        ).fetchall()
        return [int(r[0]) for r in rows]

    def arm_burst(self, burst_id: int) -> str:
        token = secrets.token_hex(4)
        with self.conn:
            self.conn.execute(
                "UPDATE bursts SET confirm_token=? WHERE id=? AND state!='running'",
                (token,burst_id),
            )
        return token

    def cancel_burst_confirmation(self, burst_id: int, token: str) -> bool:
        with self.conn:
            res = self.conn.execute(
                "UPDATE bursts SET confirm_token=NULL WHERE id=? AND confirm_token=?",
                (burst_id, token),
            )
            return res.rowcount == 1

    def start_burst(self, burst_id: int, token: str) -> bool:
        with self.conn:
            res = self.conn.execute(
                "UPDATE bursts SET state='running',confirm_token=NULL "
                "WHERE id=? AND state!='running' AND confirm_token=?",
                (burst_id,token),
            )
            return res.rowcount == 1

    def finish_burst(self, burst_id: int) -> None:
        with self.conn:
            self.conn.execute("UPDATE bursts SET state='done' WHERE id=?", (burst_id,))

    def ignore_burst(self, burst_id: int) -> None:
        with self.conn:
            self.conn.execute("UPDATE bursts SET state='ignored', confirm_token=NULL WHERE id=?", (burst_id,))

    def stats(self) -> tuple[int, int, int, int]:
        since = time.time() - BURST_WINDOW_SECONDS
        recent = int(self.conn.execute(
            "SELECT COUNT(DISTINCT user_id) FROM joins WHERE joined_at >= ?", (since,)
        ).fetchone()[0])
        total = int(self.conn.execute("SELECT COUNT(*) FROM joins").fetchone()[0])
        kept = int(self.conn.execute("SELECT COUNT(*) FROM kept").fetchone()[0])
        pending = int(self.conn.execute("SELECT COUNT(*) FROM joins WHERE decision='pending'").fetchone()[0])
        return recent, total, kept, pending

    def recent_bursts(self, limit: int = 5):
        return self.conn.execute("SELECT * FROM bursts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def latest_joins(self, limit: int = 8):
        return self.conn.execute("SELECT * FROM joins ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def store(context: ContextTypes.DEFAULT_TYPE) -> Store:
    return context.application.bot_data["store"]


def admin_chat(update: Update) -> bool:
    return bool(
        update.effective_user and update.effective_user.id == ADMIN_ID
        and update.effective_chat and update.effective_chat.type == ChatType.PRIVATE
    )


def member_present(member: ChatMember) -> bool:
    if member.status in (ChatMember.MEMBER, ChatMember.ADMINISTRATOR, ChatMember.OWNER):
        return True
    return member.status == ChatMember.RESTRICTED and bool(getattr(member, "is_member", False))


def keyboard_for_join(join_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("✅ Keep", callback_data=f"keep:{join_id}"),
        InlineKeyboardButton("🗑 Remove", callback_data=f"remove:{join_id}"),
    ]])


def keyboard_for_burst(burst_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🧹 Review bulk removal", callback_data=f"bulk:ask:{burst_id}")],
        [InlineKeyboardButton("✅ Ignore this alert", callback_data=f"bulk:ignore:{burst_id}")],
    ])


async def send_join_alert(bot, entry) -> None:
    person = html.escape(entry["display_name"][:160])
    username = f"@{html.escape(entry['username'])}" if entry["username"] else "No username"
    since = datetime.fromtimestamp(entry["joined_at"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    text = (
        "👤 <b>New channel subscriber</b>\n\n"
        f"Name: {person}\nUsername: {username}\n"
        f"User ID: <code>{entry['user_id']}</code>\n"
        f"Joined: {since}\nChannel: {html.escape(CHANNEL)}\n\n"
        "Choose <b>Keep</b> to protect this account from bulk removal, "
        "or <b>Remove</b> to ban it from the channel."
    )
    await bot.send_message(
        chat_id=ADMIN_ID,
        text=text,
        parse_mode=ParseMode.HTML,
        reply_markup=keyboard_for_join(entry["id"]),
        disable_web_page_preview=True,
    )


async def alert_worker(app: Application) -> None:
    queue: asyncio.Queue = app.bot_data["alert_queue"]
    db: Store = app.bot_data["store"]
    while True:
        join_id = await queue.get()
        try:
            event = db.join(join_id)
            if event and not event["notified"]:
                # Do not flood admin with stale action buttons after a mass removal.
                if event["decision"] not in ("removed", "left"):
                    await send_join_alert(app.bot, event)
                db.mark_alerted(join_id)
        except RetryAfter as exc:
            await asyncio.sleep(float(exc.retry_after) + 1)
            await queue.put(join_id)
        except Forbidden:
            LOG.warning("Admin has not opened the bot or has blocked it. Send /start to the bot.")
            await asyncio.sleep(30)
            await queue.put(join_id)
        except TelegramError:
            LOG.exception("Failed to send join alert %s; retrying", join_id)
            await asyncio.sleep(10)
            await queue.put(join_id)
        except Exception:
            LOG.exception("Unexpected alert worker error for %s", join_id)
        finally:
            queue.task_done()
            await asyncio.sleep(ALERT_DELAY_SECONDS)


async def post_init(app: Application) -> None:
    channel = await app.bot.get_chat(CHANNEL)
    if channel.type != ChatType.CHANNEL:
        raise RuntimeError(f"{CHANNEL} is not a Telegram channel")
    app.bot_data["channel_id"] = channel.id
    app.bot_data["channel_title"] = channel.title or CHANNEL
    myself = await app.bot.get_me()
    me = await app.bot.get_chat_member(channel.id, myself.id)
    if me.status not in (ChatMember.ADMINISTRATOR, ChatMember.OWNER):
        raise RuntimeError("Add the bot as a channel administrator before starting it")
    if not getattr(me, "can_restrict_members", False) and me.status != ChatMember.OWNER:
        raise RuntimeError("Give the bot 'Ban Users' / 'Restrict Members' administrator permission")

    queue: asyncio.Queue = asyncio.Queue(maxsize=15000)
    app.bot_data["alert_queue"] = queue
    for join_id in app.bot_data["store"].pending_alerts():
        queue.put_nowait(join_id)
    app.bot_data["worker_task"] = asyncio.create_task(alert_worker(app))
    LOG.info("Tracking channel %s (ID %s). %s pending alerts", CHANNEL, channel.id, queue.qsize())
    try:
        await app.bot.send_message(
            chat_id=ADMIN_ID,
            text=f"🛡 Subscriber Guard online for {CHANNEL}.\nUse /status or /help.",
        )
    except Forbidden:
        LOG.warning("Admin must open the bot in Telegram and tap START first")
    except TelegramError:
        LOG.exception("Startup admin notification failed")


async def post_shutdown(app: Application) -> None:
    task = app.bot_data.get("worker_task")
    if task:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    app.bot_data["store"].close()


async def member_change(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    change = update.chat_member
    if not change or change.chat.id != context.application.bot_data["channel_id"]:
        return
    user = change.new_chat_member.user
    old_present = member_present(change.old_chat_member)
    new_present = member_present(change.new_chat_member)
    db = store(context)
    if not old_present and new_present:
        if change.new_chat_member.status in (ChatMember.OWNER, ChatMember.ADMINISTRATOR):
            return
        event_id, burst_id, recent_count = db.record_join(
            update_id=update.update_id,
            user_id=user.id,
            display_name=user.full_name,
            username=user.username,
            joined_at=change.date.timestamp(),
        )
        if event_id is None:
            return
        try:
            context.application.bot_data["alert_queue"].put_nowait(event_id)
        except asyncio.QueueFull:
            LOG.error("Alert queue full. Join event %s saved in DB, alert not queued", event_id)
        if burst_id is not None:
            count, eligible = db.burst_stats(burst_id)
            LOG.warning("Burst %s opened: %d joins", burst_id, recent_count)
            try:
                await context.bot.send_message(
                    chat_id=ADMIN_ID,
                    text=(
                        f"🚨 MASS-JOIN ALERT\n\n"
                        f"{recent_count} unique accounts joined {CHANNEL} "
                        f"within {BURST_WINDOW_SECONDS // 60} minutes.\n"
                        f"Burst #{burst_id}: {count} tracked; {eligible} eligible for review.\n\n"
                        "This alone doesn't prove accounts are fake. "
                        "You decide whether to remove them.\n"
                        "New joiners arriving shortly after this alert are added to this burst."
                    ),
                    reply_markup=keyboard_for_burst(burst_id),
                )
            except TelegramError:
                LOG.exception("Couldn't send burst alert; access via /bursts")
    elif old_present and not new_present:
        db.set_user_decision(user.id, "left")


async def remove_one(bot, channel_id: int, db: Store, user_id: int) -> str:
    """Ban one user; never ban channel admins or protected users."""
    if db.is_kept(user_id):
        return "protected"
    member = await bot.get_chat_member(chat_id=channel_id, user_id=user_id)
    if member.status in (ChatMember.OWNER, ChatMember.ADMINISTRATOR):
        return "admin"
    if not member_present(member):
        db.set_user_decision(user_id, "left")
        return "already_left"
    await bot.ban_chat_member(chat_id=channel_id, user_id=user_id)
    db.set_user_decision(user_id, "removed")
    return "removed"


async def retry_removal(bot, channel_id: int, db: Store, user_id: int) -> str:
    for attempt in range(4):
        try:
            return await remove_one(bot, channel_id, db, user_id)
        except RetryAfter as exc:
            await asyncio.sleep(float(exc.retry_after) + 1)
        except (BadRequest, Forbidden) as exc:
            LOG.warning("Cannot remove user %s: %s", user_id, exc)
            return "failed"
        except TelegramError:
            LOG.exception("Telegram error removing %s (attempt %s)", user_id, attempt+1)
            await asyncio.sleep(2 * (attempt+1))
    return "failed"


async def bulk_job(app: Application, burst_id: int, chat_id: int, message_id: int) -> None:
    db: Store = app.bot_data["store"]
    selected = db.burst_candidates(burst_id)
    counts = {"removed": 0, "already_left": 0, "protected": 0, "admin": 0, "failed": 0}
    total = len(selected)
    try:
        for i, user_id in enumerate(selected, 1):
            # Each check re-tests the whitelist so the admin can still tap Keep.
            result = await retry_removal(app.bot, app.bot_data["channel_id"], db, user_id)
            counts[result] += 1
            if i % 25 == 0 or i == total:
                try:
                    await app.bot.edit_message_text(
                        chat_id=chat_id, message_id=message_id,
                        text=f"🧹 Burst #{burst_id}: processed {i}/{total}\nRemoved: {counts['removed']}\nFailed: {counts['failed']}",
                    )
                except TelegramError:
                    pass
            await asyncio.sleep(0.35)
        db.finish_burst(burst_id)
        summary = (
            f"✅ Bulk review complete — burst #{burst_id}\n\n"
            f"Removed/banned: {counts['removed']}\n"
            f"Already left: {counts['already_left']}\n"
            f"Protected or admins: {counts['protected']+counts['admin']}\n"
            f"Failed: {counts['failed']}\n\n"
            "These actions apply only to subscribers the bot observed.\n"
            "For failed removals use /bursts to retry."
        )
        try:
            await app.bot.edit_message_text(chat_id=chat_id, message_id=message_id, text=summary)
        except TelegramError:
            await app.bot.send_message(chat_id=chat_id, text=summary)
    except Exception:
        LOG.exception("Bulk job for burst %d crashed; can retry via /bursts", burst_id)
        with db.conn:
            db.conn.execute("UPDATE bursts SET state='open' WHERE id=?", (burst_id,))
        with suppress(TelegramError):
            await app.bot.send_message(chat_id=ADMIN_ID, text=f"⚠️ Burst #{burst_id} interrupted; use /bursts to retry.")


async def actions(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query:
        return
    if not admin_chat(update):
        await query.answer("Admin only", show_alert=True)
        return
    data = query.data or ""
    parts = data.split(":")
    db = store(context)
    channel_id: int = context.application.bot_data["channel_id"]
    if len(parts) == 2 and parts[0] in ("keep", "remove"):
        try:
            join_id = int(parts[1])
        except ValueError:
            await query.answer("Invalid request")
            return
        event = db.join(join_id)
        if not event:
            await query.answer("Event not found", show_alert=True)
            return
        user_id = int(event["user_id"])
        if parts[0] == "keep":
            db.keep(user_id)
            await query.answer("Kept — protected from bulk removal")
            await query.edit_message_reply_markup(reply_markup=None)
            await query.message.reply_text(f"✅ Kept {event['display_name']} (ID {user_id}). Use /unkeep {user_id} to undo.")
        else:
            if db.is_kept(user_id):
                await query.answer("Protected user. Use /unkeep first.", show_alert=True)
                return
            await query.answer("Removing subscriber…")
            result = await retry_removal(context.bot, channel_id, db, user_id)
            if result == "removed":
                await query.edit_message_reply_markup(reply_markup=None)
                await query.message.reply_text(f"🗑 Removed and banned user {user_id}.")
            else:
                await query.message.reply_text(f"Removal result for {user_id}: {result}. You can retry if needed.")
        return

    if len(parts) >= 3 and parts[0] == "bulk":
        action = parts[1]
        try:
            burst_id = int(parts[2])
        except ValueError:
            await query.answer("Invalid burst")
            return
        batch = db.burst(burst_id)
        if not batch:
            await query.answer("Burst not found", show_alert=True)
            return
        if action == "ask":
            if batch["state"] == "running":
                await query.answer("Bulk removal is already running", show_alert=True)
                return
            token = db.arm_burst(burst_id)
            total, eligible = db.burst_stats(burst_id)
            await query.answer()
            await query.message.reply_text(
                f"⚠️ CONFIRM BULK REMOVAL — burst #{burst_id}\n\n"
                f"Tracked in burst: {total}\n"
                f"Eligible right now: {eligible}\n"
                "Users you marked Keep, admins and users who left are excluded.\n\n"
                "Confirming will ban these accounts. A sudden spike alone is not proof of fraud.",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("🗑 Confirm removal", callback_data=f"bulk:go:{burst_id}:{token}"),
                    InlineKeyboardButton("Cancel", callback_data=f"bulk:cancel:{burst_id}:{token}"),
                ]]),
            )
            return
        if action == "ignore":
            if batch["state"] == "running":
                await query.answer("Removal already running", show_alert=True)
                return
            db.ignore_burst(burst_id)
            await query.answer("Alert ignored; no one was removed")
            await query.edit_message_reply_markup(reply_markup=None)
            return
        if action in ("go", "cancel") and len(parts) == 4:
            token = parts[3]
            if action == "cancel":
                ok = db.cancel_burst_confirmation(burst_id, token)
                await query.answer("Cancelled" if ok else "This confirmation expired")
                if ok:
                    await query.edit_message_text(f"✅ Bulk removal for burst #{burst_id} cancelled. No one was removed.")
                return
            if not db.start_burst(burst_id, token):
                await query.answer("Expired or already started", show_alert=True)
                return
            await query.answer("Bulk removal started")
            await query.edit_message_text(f"🧹 Processing burst #{burst_id}…")
            context.application.create_task(
                bulk_job(context.application, burst_id, query.message.chat_id, query.message.message_id),
                update=update,
            )
            return
    await query.answer("Unknown or expired action", show_alert=True)


async def command_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not admin_chat(update):
        if update.effective_chat and update.effective_chat.type == ChatType.PRIVATE:
            await update.message.reply_text("This is a private channel-admin bot.")
        return
    await update.message.reply_text(
        f"🛡 Subscriber Guard is active for {CHANNEL}.\n\n"
        "Each detected new subscriber gets Keep / Remove buttons here.\n"
        f"{BURST_THRESHOLD}+ distinct joins within {BURST_WINDOW_SECONDS // 60} minutes "
        "triggers a mass-join alert with optional confirmed bulk removal.\n\n"
        "Commands: /status, /recent, /bursts, /unkeep ID, /unban ID, /help"
    )


async def command_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await command_start(update, context)


async def command_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not admin_chat(update):
        return
    db = store(context)
    recent, total, kept, pending = db.stats()
    try:
        live = await context.bot.get_chat_member_count(context.application.bot_data["channel_id"])
    except TelegramError:
        live = "unavailable"
    queue = context.application.bot_data["alert_queue"].qsize()
    await update.message.reply_text(
        f"🛡 {CHANNEL}\n\n"
        f"Telegram subscriber count: {live}\n"
        f"Distinct joins, last {BURST_WINDOW_SECONDS // 60} min: {recent}\n"
        f"Recorded join events since bot began: {total}\n"
        f"Pending reviews: {pending}\nKept/protected users: {kept}\n"
        f"Queued notifications: {queue}\n"
        f"Mass alert threshold: {BURST_THRESHOLD} joins/{BURST_WINDOW_SECONDS // 60} min\n\n"
        "The bot cannot see members who joined before installation unless Telegram reports a new status change."
    )


async def command_recent(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not admin_chat(update):
        return
    events = store(context).latest_joins(8)
    if not events:
        await update.message.reply_text("No new subscriber events yet.")
        return
    for e in events:
        await update.message.reply_text(
            f"👤 {e['display_name']} — ID {e['user_id']}\nState: {e['decision']}",
            reply_markup=keyboard_for_join(e["id"]) if e["decision"] == "pending" else None,
        )


async def command_bursts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not admin_chat(update):
        return
    db = store(context)
    bursts = db.recent_bursts()
    if not bursts:
        await update.message.reply_text("No mass-join alerts yet.")
        return
    for b in bursts:
        total, eligible = db.burst_stats(b["id"])
        await update.message.reply_text(
            f"🚨 Burst #{b['id']} — {b['state']}\nTracked: {total}; eligible for removal: {eligible}",
            reply_markup=keyboard_for_burst(b["id"]) if b["state"] != "running" else None,
        )


async def command_unkeep(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not admin_chat(update):
        return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("Usage: /unkeep 123456789")
        return
    user_id = int(context.args[0])
    found = store(context).unkeep(user_id)
    await update.message.reply_text("Protection removed." if found else "User was not on the Keep list.")


async def command_unban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not admin_chat(update):
        return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("Usage: /unban 123456789")
        return
    user_id = int(context.args[0])
    try:
        await context.bot.unban_chat_member(
            chat_id=context.application.bot_data["channel_id"],
            user_id=user_id, only_if_banned=True,
        )
        await update.message.reply_text(f"✅ User {user_id} unbanned (not automatically re-added).")
    except TelegramError as exc:
        await update.message.reply_text(f"Could not unban: {exc}")


def main() -> None:
    if not TOKEN or ADMIN_ID <= 0:
        raise SystemExit("Set BOT_TOKEN and numeric ADMIN_ID environment variables before running.")
    if not CHANNEL.startswith("@"):
        raise SystemExit("CHANNEL_USERNAME must be like @massageservice0001")
    db = Store(DB_PATH)
    app = Application.builder().token(TOKEN).post_init(post_init).post_shutdown(post_shutdown).build()
    app.bot_data["store"] = db
    app.add_handler(ChatMemberHandler(member_change, ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(CallbackQueryHandler(actions))
    for command, function in (
        ("start", command_start), ("help", command_help),
        ("status", command_status), ("recent", command_recent),
        ("bursts", command_bursts), ("unkeep", command_unkeep),
        ("unban", command_unban),
    ):
        app.add_handler(CommandHandler(command, function))
    # CHAT_MEMBER is *not* delivered unless explicitly requested.
    app.run_polling(allowed_updates=["chat_member", "message", "callback_query"], drop_pending_updates=False)


if __name__ == "__main__":
    main()
