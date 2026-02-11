# Quick Start

For the full security analysis and architecture documentation, see the [main README](../../README.md).

---

## Before You Start (5 min prep)

Gather these credentials -- you'll be prompted for each during setup:

1. **Telegram API ID + hash** -- [my.telegram.org](https://my.telegram.org) > API development tools
2. **Bot token** -- message [@BotFather](https://t.me/BotFather) on Telegram, send `/newbot`
3. **Anthropic API key** -- [console.anthropic.com](https://console.anthropic.com/settings/keys)
4. **Your Telegram user ID** -- message [@userinfobot](https://t.me/userinfobot) on Telegram
5. **Voyage AI API key** (optional) -- [dash.voyageai.com](https://dash.voyageai.com) for semantic search

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
3. **Credentials** -- prompts for all keys/tokens, stores them in the system keychain
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
| Telethon session | `/home/tg-syncer/.telethon/` (encrypted, `0700`) |
| Syncer service | `/etc/systemd/system/tg-syncer.service` |
| Query bot service | `/etc/systemd/system/tg-querybot.service` |
| Firewall rules | `/etc/nftables.d/tg-assistant-firewall.conf` |

---

## Common Commands

```bash
# Check service status
systemctl status tg-syncer tg-querybot

# View syncer logs (live)
journalctl -u tg-syncer -f

# View query bot logs (live)
journalctl -u tg-querybot -f

# View audit log
tail -f /var/log/tg-assistant/audit.log

# Restart after config change
sudo systemctl restart tg-syncer tg-querybot

# Monitor network traffic (30-second capture)
sudo ./scripts/monitor-network.sh 30
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
ls -la /home/tg-syncer/.telethon/

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

---

## Security Verification

```bash
# Run the full security test suite
sudo ./tests/security-verification.sh

# Verify only expected network traffic
sudo tcpdump -i any -n 'not host api.telegram.org and not host api.anthropic.com and not localhost' -c 10

# Check for injection attempts in audit log
grep -i "injection\|blocked\|denied" /var/log/tg-assistant/audit.log

# Verify config file permissions (should be 600)
stat -c '%a %U:%G %n' /etc/tg-assistant/settings.toml

# Verify session file permissions (should be 0700 directory, 0600 files)
sudo ls -la /home/tg-syncer/.telethon/

# Check active Telethon sessions on your account
# Open Telegram > Settings > Devices
```

---

## Updating

```bash
cd ~/tg-assistant
git pull

# Update Python dependencies
source /opt/tg-assistant/venv/bin/activate
pip install -r requirements.txt

# Restart services
sudo systemctl restart tg-syncer tg-querybot

# Re-verify security after updates
sudo ./tests/security-verification.sh
```
