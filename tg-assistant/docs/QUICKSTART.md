# Telelocal Quick Start

Get Telelocal running and start querying your Telegram history.

---

## Prerequisites

Have these ready:

1. Telegram API ID + hash: [my.telegram.org](https://my.telegram.org)
2. Bot token: [@BotFather](https://t.me/BotFather)
3. Anthropic API key: [console.anthropic.com](https://console.anthropic.com/settings/keys)
4. Your Telegram user ID: [@userinfobot](https://t.me/userinfobot)

Recommended host:

- Raspberry Pi 4 (4GB+) or Pi 5
- Raspberry Pi OS 64-bit or Ubuntu 22.04+ ARM64
- 32GB+ storage (SSD preferred)
- Ethernet preferred

---

## Install and Verify

```bash
git clone https://github.com/obheda12/telelocal.git
cd telelocal/tg-assistant
sudo ./scripts/setup.sh
```

Setup prompts you for credentials (stored via encrypted credstore), creates your Telegram session, then configures chat scope and per-chat exclusions.

During Telegram session setup, Telethon will prompt "Please enter your phone (or bot token):" — **enter your phone number in full international format with country code** (e.g., `+11231231234`). Do not enter a bot token here. The connection will fail if the country code is missing or the format is wrong.

Once setup completes, verify everything is running:

```bash
telelocal status          # both services should be active
telelocal sync-status     # message/chat counts should appear
sudo ./tests/security-verification.sh
```

Check that:

- `tg-syncer` and `tg-querybot` are both running,
- no plaintext `.session` file exists in `/var/lib/tg-syncer/` (a temporary runtime `.session` in `/dev/shm` is expected while syncer runs),
- nftables rules are active for both service users.

Now send your first query to the bot:

- `/summary 1d quick`

Confirm non-owner accounts get no response. Initial sync may take 10–30+ minutes on large accounts — query quality improves as more chats are ingested.

If sync count stays at zero for 15+ minutes, see [Troubleshooting](#troubleshooting).

---

## How Sync and Pruning Work

Once running, the syncer **continuously pulls new messages** in a loop. After each pass it sleeps for `sync_interval_seconds` (default **5 minutes**, configurable in `settings.toml` under `[syncer]`), then fetches new messages from active chats freshest-first. No manual triggering is needed — the corpus stays up to date automatically.

Old messages are **pruned automatically** by a systemd timer (`tg-prune-history.timer`) that runs **every hour**. It deletes messages older than `syncer.max_history_days` (default 30 days) and removes orphaned chats with no remaining messages. Set `max_history_days = 0` to disable pruning and keep all history.

| Setting | Default | Effect |
|---------|---------|--------|
| `syncer.sync_interval_seconds` | `300` (5 min) | Time between sync passes |
| `syncer.max_history_days` | `30` | Messages older than this are pruned; `0` disables pruning |
| `syncer.max_active_chats` | `500` | Max chats scanned per pass (freshest first) |

You can manually trigger a prune at any time with `sudo telelocal prune`.

---

## Usage

The bot is your personal search and triage interface over your synced Telegram history. You interact with it by messaging your bot in Telegram.

### Natural language queries

The primary way to use the bot is to just ask it things in plain text. The system extracts your intent (target chats, senders, time range, keywords), runs a scoped search over your local corpus, and has Claude synthesize an answer.

Examples:

- "What needs my attention from the past 24 hours?"
- "Summarise the discussion in DevChat yesterday"
- "What did team X decide about pricing this week?"
- "Find messages about the Python deployment"
- "Quick synopsis of the 50 freshest chats"

This is especially useful for **BD and relationship management** — keeping track of open asks, follow-ups owed, and commitments across many concurrent conversations. Instead of scrolling through dozens of chats, ask the bot who's waiting on you, what was agreed, or what needs a response.

### Commands

Commands give you structured, repeatable queries with time-window and detail controls:

| Command | What it does |
|---------|-------------|
| `/bd [1d\|3d\|1w] [10\|25\|50\|100] [quick\|detailed]` | Freshest chat briefing — status, key updates, and actions needed |
| `/mentions [1d\|3d\|1w] [quick\|detailed]` | Items that likely need your reply (mentions, direct questions) |
| `/summary [1d\|3d\|1w] [quick\|detailed]` | Cross-chat recap: decisions, blockers, action items |
| `/more` | Continue a long response that was auto-chunked |
| `/iam [@alias1 ...]` | Bind your identity so the bot can find your mentions accurately |
| `/stats` | Database and sync statistics |

Time windows: `1d`, `3d`, `1w`. Chat counts (for `/bd`): `10`, `25`, `50`, `100`. Detail modes: `quick` (concise) or `detailed` (thorough). All parameters are optional and can be combined in any order. Long responses are automatically split and continued with `/more`.

### Host management

Everything is managed through the `telelocal` CLI on the host.

**Setup and teardown:**

| Command | What it does |
|---------|-------------|
| `sudo telelocal setup` | Full guided deployment — credentials, DB, services, firewall |
| `sudo telelocal session` | Create or recreate the Telethon session |
| `sudo telelocal wipe` | Destroy all credentials, sessions, DB, and state — clean slate |

**Daily operations:**

| Command | What it does |
|---------|-------------|
| `telelocal status` | Service health, credential state, DB message/chat counts |
| `telelocal sync-status` | Ingestion progress per chat with last activity times |
| `telelocal logs` | Tail both service logs (`logs syncer` or `logs querybot` for one) |
| `sudo telelocal manage-chats` | Interactively include/exclude chats from sync scope |
| `sudo telelocal restart` | Restart both services (also: `stop`, `start`) |
| `sudo telelocal prune` | Prune DB history older than configured retention window |

**Updating:**

```bash
cd ~/telelocal/tg-assistant
git pull
sudo telelocal update ~/telelocal/tg-assistant
sudo ./tests/security-verification.sh
```

`telelocal update` copies code into `/opt/tg-assistant` without touching runtime assets (`venv`, `models`), then restarts services.

**Incident response:**

If compromise is suspected, stop services immediately and run the emergency revocation script:

```bash
sudo telelocal stop
sudo ./scripts/emergency-revoke.sh
```

See [SECURITY_MODEL.md](SECURITY_MODEL.md) for full incident response procedures.

---

## Tuning

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

## Reference

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

## Troubleshooting

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
sudo telelocal setup
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
sudo telelocal stop
sudo telelocal session
sudo telelocal start
```

### Rate-limiting symptoms

```bash
journalctl -u tg-syncer --since "1 hour ago" | grep -i flood
```

The syncer already applies backoff; avoid lowering rate limits aggressively.

---

For security incident response procedures, see [SECURITY_MODEL.md](SECURITY_MODEL.md).

Related docs:

- `SECURITY_MODEL.md` (authoritative security model, threat catalog, incident response)
- `TELETHON_HARDENING.md` (Telethon-specific controls)
