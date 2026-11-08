# NomardDesk Subscriber Guard — Railway edition

Telegram public-channel moderation bot for `@massageservice0001` with **Keep / Remove** actions for each **observed** new subscriber and optional two-step confirmed mass removal after **200 unique joins in 10 minutes**. No verification for users.

**Deploy:** Read [`RAILWAY_SETUP.md`](RAILWAY_SETUP.md) for Telegram permissions, Railway Variables, one-replica setup, and a `/data` persistent volume. Railway automatically detects `Dockerfile` and runs `python bot.py`.

**Required Railway variables:** `BOT_TOKEN`, `ADMIN_ID`, `CHANNEL_USERNAME=@massageservice0001`, `DB_PATH=/data/guard.db`.

**Limitations:** Telegram must deliver `chat_member` updates; the bot cannot list every historical subscriber, and joining quickly does not prove an account is fake. Removal only happens after your button press or a separately confirmed batch.

**Test:** `python test_store.py` (offline database tests). Test live delivery with a second Telegram account once deployed.
