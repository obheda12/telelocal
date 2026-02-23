# Telelocal Quick Start

This guide is optimized for operators who want:

- secure local-first Telegram indexing,
- fast ingestion for high chat counts,
- clear day-2 commands with minimal operational overhead.

For full threat analysis and control rationale, see:

- `../../README.md`
- `ARCHITECTURE.md`
- `THREAT_MODEL.md`
- `SECURITY_MODEL.md`
- `TELETHON_HARDENING.md`

---

## 1. Before You Run Setup

Have these ready:

1. Telegram API ID + hash: [my.telegram.org](https://my.telegram.org)
2. Bot token: [@BotFather](https://t.me/BotFather)
3. Anthropic API key: [console.anthropic.com](https://console.anthropic.com/settings/keys)
4. Your Telegram user ID: [@userinfobot](https://t.me/userinfobot)

Recommended host profile:

- Raspberry Pi 4 (4GB+) or Pi 5
- Raspberry Pi OS 64-bit or Ubuntu 22.04+ ARM64
- 32GB+ storage (SSD preferred)
- Ethernet preferred

---

## 2. Fast Deploy (Copy/Paste)

```bash
git clone <your-repo-url> telelocal
cd telelocal/tg-assistant
sudo ./scripts/setup.sh
```

Then verify runtime:

```bash
telelocal status
telelocal sync-status
telelocal logs
```

Setup prompts you for:

- credentials (stored via encrypted credstore),
- chat-type scope (exclude channels and/or direct user DMs),
- optional per-chat include/exclude selection before first sync starts.

---

## 3. Security-Critical Post-Install Checks

Run these once immediately after deploy:

```bash
sudo ./tests/security-verification.sh
telelocal status
telelocal sync-status
```

Expected outcomes:

- `tg-syncer` and `tg-querybot` are running.
- message/chat counts increase over time.
- no plaintext `.session` file exists in `/var/lib/tg-syncer/` (a temporary runtime `.session` file in `/dev/shm` is expected while `tg-syncer` is running).
- nftables rules are active for both service users.

If the sync count stays at zero for 15+ minutes, go to [Troubleshooting](#8-troubleshooting).

---

## 4. First 15-Minute Validation

1. Send one query to your bot:
   - `/summary 1d quick`
2. Confirm owner-only behavior:
   - non-owner accounts should get no response.
3. Confirm ingestion progress:
   - `telelocal sync-status` should show active chats and message growth.

Initial sync expectations:

- first pass may take 10-30+ minutes on large accounts,
- quality improves as more chats are ingested.

---

## 5. Day-2 Commands

| Need | Command |
|------|---------|
| Service health | `telelocal status` |
| Ingestion progress | `telelocal sync-status` |
| Runtime logs | `telelocal logs` |
| Scope/exclusions management | `sudo telelocal manage-chats` |
| Restart both services (non-blocking wrapper) | `sudo telelocal restart` |
| Safe code deploy to `/opt` | `sudo telelocal update <path-to-clone>` |
| History pruning | `sudo telelocal prune` |

Common query commands:

- `/mentions 1d quick`
- `/summary 1d quick`
- `/summary 1w detailed`
- `/fresh 25 quick`
- `/more`

---

## 6. Scope And Throughput Tuning

Highest-impact knobs in `settings.toml`:

| Setting | Typical value | Why it matters |
|---------|---------------|----------------|
| `syncer.max_active_chats` | `500` | Caps each pass to freshest chats, big win for large accounts |
| `syncer.max_history_days` | `30` | Bounds initial fetch depth per chat |
| `syncer.include_chat_types` | `["group"]` or `["group","channel"]` | Reduces noise and ingest load |
| `syncer.defer_embeddings` | `true` | Decouples embedding work from ingest write path |
| `querybot.max_intent_chats` | `200` | Reduces intent extraction latency on huge chat lists |

Tips:

- keep `syncer.enable_prescan_progress = false` for faster pass startup,
- keep `syncer.store_raw_json = false` unless you explicitly need raw payloads,
- use `sudo telelocal manage-chats` to adjust per-chat exclusions and keyword-based bulk filtering.

---

## 7. Important File Locations

| Description | Path |
|-------------|------|
| Config | `/etc/tg-assistant/settings.toml` |
| System prompt | `/etc/tg-assistant/system_prompt.md` |
| Excluded chats file | `/etc/tg-assistant/excluded_chats.json` |
| Audit log | `/var/log/tg-assistant/audit.log` |
| Encrypted Telethon session | `/var/lib/tg-syncer/tg_syncer_session.session.enc` |
| Syncer unit | `/etc/systemd/system/tg-syncer.service` |
| Querybot unit | `/etc/systemd/system/tg-querybot.service` |
| API allowlist refresh timer | `/etc/systemd/system/tg-refresh-api-ipsets.timer` |
| Prune timer | `/etc/systemd/system/tg-prune-history.timer` |
| Firewall rules | `/etc/nftables.d/tg-assistant-firewall.conf` |

---

## 8. Troubleshooting

### `sync-status` shows 0 messages

```bash
telelocal status
telelocal logs
```

Then check:

- session exists: `/var/lib/tg-syncer/tg_syncer_session.session.enc`,
- credstore entries exist in `/etc/credstore.encrypted/`,
- scope is not over-restricted (`include_chat_types`, exclusions),
- `max_active_chats` is not too low for your desired coverage.

### Service restart appears to hang

Use the wrapper:

```bash
sudo telelocal restart
```

Direct `systemctl restart` may block while syncer is in a long stop path.

### `status=203/EXEC` after update

Usually means `/opt/tg-assistant/venv/bin/python3` is missing (often from unsafe `rsync --delete`).

```bash
cd ~/telelocal/tg-assistant
sudo telelocal update ~/telelocal/tg-assistant
```

If venv is missing entirely:

```bash
sudo ./scripts/setup.sh
```

### Bot does not respond

```bash
read -rsp "Bot token: " BOT_TOKEN; echo
curl -s "https://api.telegram.org/bot${BOT_TOKEN}/getMe" | python3 -m json.tool
unset BOT_TOKEN
```

Also verify:

- `owner_telegram_id` is correct in config,
- you are messaging from the owner account.

### Telethon session invalidated

```bash
sudo systemctl stop tg-syncer
sudo ./scripts/setup-telethon-session.sh
sudo systemctl start tg-syncer
```

### Rate-limiting symptoms

```bash
journalctl -u tg-syncer --since "1 hour ago" | grep -i flood
```

The syncer already applies backoff; avoid lowering rate limits aggressively.

---

## 9. Updating Safely

```bash
cd ~/telelocal/tg-assistant
git pull
sudo telelocal update ~/telelocal/tg-assistant
sudo ./tests/security-verification.sh
```

Avoid direct `rsync --delete` into `/opt/tg-assistant` unless you preserve runtime assets (`venv`, `models`).

Optional embedding backfill after upgrades:

```bash
TG_ASSISTANT_DB_USER=postgres /opt/tg-assistant/venv/bin/python3 /opt/tg-assistant/scripts/backfill-embeddings.py
```

---

## 10. Security Incident Quick Actions

If compromise is suspected:

1. Stop services:
   - `sudo systemctl stop tg-syncer tg-querybot`
2. Revoke Telegram session from another trusted Telegram client:
   - Telegram -> Settings -> Devices
3. Rotate:
   - Telegram API ID/hash
   - Telethon session + session encryption key
   - Bot token
   - Claude API key
4. Preserve logs and run:
   - `sudo ./tests/security-verification.sh`
5. Recreate session and restart services only after review.

Critical note:

- A usable Telethon session is effectively account-level compromise.
