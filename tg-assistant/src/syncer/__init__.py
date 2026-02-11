"""
Syncer package — reads messages from Telegram via the User API (MTProto/Telethon)
and stores them in PostgreSQL.

All Telegram API access goes through ReadOnlyTelegramClient to enforce
a strict read-only allowlist.  The syncer process runs under a dedicated
system user (tg-syncer) with its own DB role (syncer_role: INSERT/SELECT).
"""
