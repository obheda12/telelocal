# Quick Start

For the full security analysis and architecture documentation, see the [main README](../../README.md).

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

## Deploy (15-20 min)

```bash
git clone <your-repo-url> tg-assistant
cd tg-assistant
sudo ./scripts/setup.sh
```

The setup script handles everything in order:

1. **Pre-flight** -- platform, sudo, internet checks
2. **System setup** -- apt packages, Python 3.11+, PostgreSQL + pgvector, system users, venv, systemd services, nftables
3. **Credentials** -- prompts for all keys/tokens, stores them in the encrypted credstore (systemd-creds)
4. **Configuration** -- injects your values into `settings.toml`
5. **Telethon session** -- interactive login (phone, code, 2FA), encrypts and stores the session
6. **Security verification** -- checks permissions, firewall, DB roles, encryption
7. **Service activation** -- enables systemd services, optionally starts them

### Granular control

If you prefer to run steps individually:

```bash
sudo ./scripts/setup-raspberry-pi.sh    # Infrastructure only
sudo ./scripts/setup-telethon-session.sh # Session creation only
```

---

## Verify

Message your bot on Telegram. Ask a question about your chats.

```bash
# Check service status
systemctl status tg-syncer tg-querybot

# Watch logs
journalctl -u tg-syncer -f
journalctl -u tg-querybot -f
```

---

## File Locations

| Description | Path |
|-------------|------|
| Configuration | `/etc/tg-assistant/settings.toml` |
| System prompt | `/etc/tg-assistant/system_prompt.md` |
| Audit logs | `/var/log/tg-assistant/audit.log` |
| Telethon session | `/var/lib/tg-syncer/` (encrypted, `0700`) |
| Syncer service | `/etc/systemd/system/tg-syncer.service` |
| Query bot service | `/etc/systemd/system/tg-querybot.service` |
| API IP refresh timer | `/etc/systemd/system/tg-refresh-api-ipsets.timer` |
| Firewall rules | `/etc/nftables.d/tg-assistant-firewall.conf` |

---

## Common Commands

```bash
# Check service status
systemctl status tg-syncer tg-querybot
systemctl status tg-refresh-api-ipsets.timer

# View syncer logs (live)
journalctl -u tg-syncer -f

# View query bot logs (live)
journalctl -u tg-querybot -f

# View API allowlist refresh logs
journalctl -u tg-refresh-api-ipsets.service -n 50 --no-pager

# View audit log
tail -f /var/log/tg-assistant/audit.log

# Restart after config change
sudo systemctl restart tg-syncer tg-querybot

# Monitor network traffic (30-second capture)
sudo ./scripts/monitor-network.sh 30

# Benchmark ingestion + query latency
./scripts/benchmark-pipeline.sh
```

---

## Troubleshooting

### Service won't start

```bash
journalctl -u tg-syncer -n 100 --no-pager
journalctl -u tg-querybot -n 100 --no-pager

# Common causes: missing credentials, bad permissions, Python import errors
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
- Set `syncer.max_active_chats = 500` (or lower) to focus ingest on freshest chats and reduce full-pass latency on large accounts.
- Keep `syncer.store_raw_json = false` unless you explicitly need full raw payloads.
- For faster catch-up on many chats, keep a small `syncer.idle_chat_delay_seconds` (default `0.1`).
- The syncer now batches per-chat high-water-mark lookups into one DB query per pass for lower latency on large chat counts.
- Query-time searches with `search_terms` run as a single SQL hybrid rank (FTS + vector), reducing round-trips and Python merge overhead.
- Tune `querybot.hybrid_min_terms` / `querybot.hybrid_min_term_length` to skip vector work on short keyword queries and reduce p95 latency.
- If you have hundreds of chats, tune `querybot.max_intent_chats` (default `200`) to reduce intent extraction latency/cost.
- For the fastest ingest on large/busy accounts, enable `syncer.defer_embeddings = true` to decouple message writes from embedding generation.
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
cd ~/telenad/tg-assistant
git pull

# Deploy to /opt without deleting runtime assets (venv/models)
sudo ./scripts/deploy-update.sh

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
