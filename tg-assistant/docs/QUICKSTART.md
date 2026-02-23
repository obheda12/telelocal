# Telelocal Quick Start

For the full security analysis and architecture documentation, see the [main README](../../README.md).

Use this page by phase:

| Phase | What to do |
|-------|------------|
| Deploy | Run setup once and complete prompts |
| Verify | Confirm sync + bot behavior |
| Operate | Use `telelocal` commands and tune scope/perf |

---

## Before You Start (5 min prep)

Gather these credentials -- you'll be prompted for each during setup:

1. **Telegram API ID + hash** -- [my.telegram.org](https://my.telegram.org) > API development tools
2. **Bot token** -- message [@BotFather](https://t.me/BotFather) on Telegram, send `/newbot`
3. **Anthropic API key** -- [console.anthropic.com](https://console.anthropic.com/settings/keys)
4. **Your Telegram user ID** -- message [@userinfobot](https://t.me/userinfobot) on Telegram

### Hardware

- Raspberry Pi 4 (4GB+) or Pi 5
- Raspberry Pi OS 64-bit or Ubuntu 22.04+ ARM64
- 32GB+ SD card or USB SSD (SSD recommended)
- Stable internet (Ethernet preferred)
- SSH access configured

---

## Fast Path (Copy/Paste)

```bash
git clone <your-repo-url> telelocal
cd telelocal/tg-assistant
sudo ./scripts/setup.sh
telelocal status
telelocal sync-status
```

If `sync-status` shows zero messages right after setup, that is normal while initial ingestion starts.

What setup will ask you:
- credentials (Telegram API ID/hash, bot token, Claude key, owner user ID)
- chat type scope (exclude channels and/or direct user DMs)
- optional per-chat include/exclude selector before first sync starts

---

## Deploy (15-20 min)

If you already ran Fast Path, skip this section and continue to [Verify](#verify).

```bash
git clone <your-repo-url> telelocal
cd telelocal/tg-assistant
sudo ./scripts/setup.sh
```

The setup script handles everything in order:

1. **Pre-flight** -- platform, sudo, internet checks
2. **System setup** -- apt packages, Python 3.11+, PostgreSQL + pgvector, system users, venv, systemd services, nftables
3. **Credentials** -- prompts for all keys/tokens, stores them in the encrypted credstore (systemd-creds)
4. **Configuration** -- injects your values into `settings.toml`, including chat-type scope prompt (exclude channels and/or user DMs if desired)
5. **Telethon session** -- interactive login (phone, code, 2FA), encrypts and stores the session
6. **Security verification** -- checks permissions, firewall, DB roles, encryption
7. **Service activation** -- optional per-chat include/exclude selector, then enables and starts services

### Granular control

If you prefer to run steps individually:

```bash
sudo ./scripts/setup-raspberry-pi.sh    # Infrastructure only
sudo ./scripts/setup-telethon-session.sh # Session creation only
```

---

## Verify

Message your bot on Telegram. Ask a question about your chats.

CLI-first health checks:

```bash
telelocal status
telelocal sync-status
telelocal logs
```

Initial sync expectations:
- First pass can take 10-30+ minutes depending on chat count and message volume.
- `telelocal sync-status` should show chats and message count rising over time.
- If counts are flat for a long period, run `telelocal logs` and see troubleshooting below.

First 15-minute success criteria:
- `telelocal status` shows `tg-syncer` and `tg-querybot` running.
- `telelocal sync-status` shows either growing message counts or an active in-progress chat.
- Bot responds to `/summary 1d quick` or `/mentions 1d quick` without auth errors.

Recommended bot command patterns:
- `/mentions 1d quick` -- triage what likely needs your reply today
- `/summary 1d quick` -- high-level daily recap
- `/summary 1w detailed` -- weekly deeper recap
- `/fresh 25 quick` -- snapshot of freshest chats
- `/more` -- continue a long response

---

## Daily Commands (Most Useful)

```bash
telelocal status
telelocal sync-status
telelocal logs
sudo telelocal manage-chats
sudo telelocal restart
```

---

## File Locations

| Description | Path |
|-------------|------|
| Configuration | `/etc/tg-assistant/settings.toml` |
| System prompt | `/etc/tg-assistant/system_prompt.md` |
| Chat exclusions | `/etc/tg-assistant/excluded_chats.json` |
| Audit logs | `/var/log/tg-assistant/audit.log` |
| Telethon session | `/var/lib/tg-syncer/` (encrypted, `0700`) |
| Syncer service | `/etc/systemd/system/tg-syncer.service` |
| Query bot service | `/etc/systemd/system/tg-querybot.service` |
| API IP refresh timer | `/etc/systemd/system/tg-refresh-api-ipsets.timer` |
| History prune timer | `/etc/systemd/system/tg-prune-history.timer` |
| Firewall rules | `/etc/nftables.d/tg-assistant-firewall.conf` |

---

## Common Commands

| Task | Command |
|------|---------|
| Health | `telelocal status` |
| Ingestion progress | `telelocal sync-status` |
| Runtime logs | `telelocal logs` |
| Change include/exclude scope | `sudo telelocal manage-chats` |
| Restart services | `sudo telelocal restart` |
| Prune by retention window | `sudo telelocal prune` |
| Deploy latest checked-out code | `sudo telelocal update ~/telelocal/tg-assistant` |
| API allowlist refresh logs | `journalctl -u tg-refresh-api-ipsets.service -n 50 --no-pager` |
| Audit log tail | `tail -f /var/log/tg-assistant/audit.log` |
| Network monitor (30s) | `sudo ./scripts/monitor-network.sh 30` |
| Pipeline benchmark | `./scripts/benchmark-pipeline.sh` |

---

## Sync Scope Knobs (Important)

These three settings control ingestion volume and speed the most:

| Setting | Recommended default | Effect |
|---------|---------------------|--------|
| `syncer.max_active_chats` | `500` | Limits each pass to freshest chats only (highest impact on large accounts). |
| `syncer.max_history_days` | `30` | Limits how far back each chat is fetched during initial sync. |
| `syncer.include_chat_types` | `["group"]` or `["group","channel"]` | Reduces non-essential sources (DM/channel noise). |

Use `sudo telelocal manage-chats` for per-chat include/exclude changes and keyword-based bulk filtering.

---

## Troubleshooting

### `sync-status` stays at 0 messages

```bash
telelocal status
telelocal logs
```

Then verify:
- Telethon session exists at `/var/lib/tg-syncer/`.
- Syncer credentials exist in `/etc/credstore.encrypted/` (`tg-assistant-api-id`, `tg-assistant-api-hash`, `session_encryption_key`).
- Chat scope is not over-restricted (`syncer.include_chat_types` and exclusions).

### Service won't start

```bash
telelocal status
telelocal logs

# If you need deeper detail:
journalctl -u tg-syncer -n 100 --no-pager
journalctl -u tg-querybot -n 100 --no-pager

# Common causes: missing credentials, bad permissions, Python import errors
```

### `restart` seems to hang

`systemctl restart` can block while the syncer exits mid-sync. Use the non-blocking wrapper:

```bash
sudo telelocal restart
```

Then check live state:

```bash
telelocal status
telelocal sync-status
```

### `status=203/EXEC` after update

This usually means the deploy target lost `/opt/tg-assistant/venv/bin/python3` (often from manual `rsync --delete` into `/opt`).

```bash
# From your git checkout
cd ~/telelocal/tg-assistant
sudo telelocal update ~/telelocal/tg-assistant
```

If `venv` is missing entirely, rerun setup:

```bash
sudo ./scripts/setup.sh
```

### Database connection failed

```bash
systemctl status postgresql
sudo -u postgres psql -c "SELECT 1;"
sudo -u postgres psql -c "\du" | grep -E "syncer|querybot"
```

### Bot not responding

```bash
# Verify the bot token is valid
curl -s "https://api.telegram.org/bot<YOUR_TOKEN>/getMe" | python3 -m json.tool

# Check that owner_telegram_id in settings.toml matches your Telegram user ID
# The bot silently ignores messages from non-owner accounts
```

### Telethon session errors

```bash
ls -la /var/lib/tg-syncer/

# Session expired or invalidated -- recreate it
sudo systemctl stop tg-syncer
sudo ./scripts/setup-telethon-session.sh
sudo systemctl start tg-syncer
```

### Rate limiting

```bash
journalctl -u tg-syncer --since "1 hour ago" | grep -i flood

# Telegram enforces strict rate limits on the User API (MTProto).
# The syncer has built-in backoff and will retry automatically.
# Do NOT decrease the sync interval below the configured default.
```

### Performance tuning

- Keep `syncer.enable_prescan_progress = false` unless you need detailed ETA logs.
- Keep `syncer.store_raw_json = false` unless you explicitly need full raw payloads.
- For faster catch-up on many chats, keep a small `syncer.idle_chat_delay_seconds` (default `0.1`).
- For fastest ingest on large/busy accounts, keep `syncer.defer_embeddings = true`.
- Tune `querybot.hybrid_min_terms` / `querybot.hybrid_min_term_length` to skip vector work on short keyword queries.
- If you have hundreds of chats, tune `querybot.max_intent_chats` (default `200`) to reduce intent extraction latency/cost.
- For cross-chat recaps, ask `"quick synopsis of the 50 freshest chats"` (breadth mode, bounded by querybot recent-summary settings).
- Retention pruning runs hourly via `tg-prune-history.timer`; run `sudo telelocal prune` manually if needed.
- Use `./scripts/benchmark-pipeline.sh` after changes and compare p95 latency before/after.

---

## Security Verification

```bash
# Run the full security test suite
sudo ./tests/security-verification.sh

# Verify only expected network traffic
sudo tcpdump -i any -n 'not host api.telegram.org and not host api.anthropic.com and not localhost' -c 10

# Check for injection attempts in audit log
grep -i "injection\|blocked\|denied" /var/log/tg-assistant/audit.log

# Verify config file permissions (should be 644)
stat -c '%a %U:%G %n' /etc/tg-assistant/settings.toml

# Verify session file permissions (should be 0700 directory, 0600 files)
sudo ls -la /var/lib/tg-syncer/

# Check active Telethon sessions on your account
# Open Telegram > Settings > Devices
```

---

## Updating

```bash
cd ~/telelocal/tg-assistant
git pull

# Deploy to /opt without deleting runtime assets (venv/models)
sudo ./scripts/deploy-update.sh
# or: sudo telelocal update ~/telelocal/tg-assistant

# Re-verify security after updates
sudo ./tests/security-verification.sh
```

Avoid `rsync --delete` directly into `/opt/tg-assistant` unless you exclude
`venv` and `models`, otherwise services may fail to start.

### Optional: backfill embeddings

If you upgraded from an older install or changed embedding settings, you may
need to backfill missing embeddings:

```bash
TG_ASSISTANT_DB_USER=postgres /opt/tg-assistant/venv/bin/python3 /opt/tg-assistant/scripts/backfill-embeddings.py
```
