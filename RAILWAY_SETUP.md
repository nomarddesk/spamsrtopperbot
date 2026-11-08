# Deploy NomardDesk Subscriber Guard on Railway

This is a Telegram **long-polling background service**. It does not need a website, HTTP port, public domain, Telegram webhook or cron schedule.

## 1. Prepare Telegram

1. Create a bot with [@BotFather](https://t.me/BotFather), using `/newbot`. Keep the token private.
2. Get your numerical Telegram user ID from [@userinfobot](https://t.me/userinfobot).
3. In **@massageservice0001** > Administrators > Add Administrator, add the bot and give it **Ban Users** (Telegram may call the permission *Restrict Members*).
4. Open the bot's private chat and tap **Start**. Only your `ADMIN_ID` can use its controls.

## 2. Create a Railway service

1. Extract the downloaded ZIP. Upload its contents **at the root** of a new GitHub repository. Important: `Dockerfile` and `bot.py` should appear at the repository root, not inside a second nested folder.
2. Visit https://railway.com/new, create a project and choose **Deploy from GitHub repo**. Select that repository and create the service.
3. Railway auto-detects the `Dockerfile`; its command is `python bot.py`.
4. Configure the service as a continuously running service, **one replica**, not a cron job. Do not enable Serverless/App Sleeping.
5. There is no need to generate a Railway public domain or configure a health-check URL.

## 3. Railway Variables

Under the bot service's **Variables** tab, add the following:

| Key | Value |
|---|---|
| `BOT_TOKEN` | Your new BotFather token |
| `ADMIN_ID` | Your numeric Telegram account ID |
| `CHANNEL_USERNAME` | `@massageservice0001` |
| `DB_PATH` | `/data/guard.db` |
| `BURST_THRESHOLD` | `200` |
| `BURST_WINDOW_MINUTES` | `10` |
| `ALERT_DELAY_SECONDS` | `1.2` |

Never publish the real BOT_TOKEN in your code or GitHub. Railway variables are applied when you deploy/redeploy the service.

## 4. Persistent storage (important)

1. Open the Railway project's service canvas and add a **Volume** attached to the **same bot service**.
2. Set the volume **Mount path** to `/data`.
3. Redeploy or apply pending staged changes.
4. Confirm `DB_PATH=/data/guard.db` in Variables. This preserves join events, Keep decisions, and burst alerts when the service restarts or deploys.

If the service starts without this volume, SQLite could write to a non-persistent location and lose data upon redeploy. The bot expects write permission to `/data`.

## 5. Check that it works

1. Open Railway > bot service > **Deployments / Logs**.
2. Look for `Tracking channel @massageservice0001`.
3. Message the bot `/status` in your own Telegram account.
4. Have a second Telegram account newly join the public channel, and confirm you receive a **Keep / Remove** alert.
5. Test a removal only on a controlled test account. **Remove bans the user**; `/unban USER_ID` reverses the ban but does not add the user back.
6. To simulate a 200-member surge without using real followers, run `python test_store.py` locally; this tests the SQLite burst and Keep logic but not Telegram delivery.

## Troubleshooting

- **Application won't start; `Set BOT_TOKEN...`**: check Railway Variables and redeploy.
- **`Add the bot as a channel administrator`**: give admin access to the exact public channel username and ensure `Ban Users` is enabled.
- **No alerts**: bot must be administrator, private bot chat started; check logs and test a **new** join after deployment. Telegram must send `chat_member` updates; the bot cannot list historical members or guarantee every event arrives.
- **`Conflict: terminated by other getUpdates request`**: another copy is polling the same BOT_TOKEN. Stop the Render deployment/other Railway service and keep exactly **one** running bot instance.
- **`unable to open database file`**: confirm volume is attached to this service at `/data`, `DB_PATH` is `/data/guard.db`, and container can write to the mounted folder.
- **Railway asks for a port/domain**: this is a worker, not a website; no inbound HTTP port is needed.

## Behavior / limitations

- The channel remains public; no join-request gate or CAPTCHA is added.
- Telegram must send a `chat_member` update for a new subscriber. Bots cannot enumerate all subscribers of a channel or retrieve all historical joiners.
- Every observed new subscriber generates an alert with **Keep / Remove**. **Keep** excludes that account from later bulk-removal actions, until you run `/unkeep USER_ID`.
- At 200 distinct joins in 10 minutes, you receive a bulk alert. **You must review and confirm** before anyone is removed. The bot does not assume a mass join proves accounts are fake.
- The bot records the users it observes and can only ban those known IDs.
- Ensure only **one replica** is running; two polling instances can conflict.
