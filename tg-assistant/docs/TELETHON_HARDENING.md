# Telethon Security Hardening Guide

Telethon-specific security controls for the Telegram Personal Assistant. Companion to [SECURITY_MODEL.md](SECURITY_MODEL.md).

Telethon is the highest-risk component. A compromised session grants **full account access** — read, send, delete, change settings, impersonate you. Every control here exists to contain that risk.

---

## Table of Contents

- [1. Why Telethon Is Different from Bot API](#1-why-telethon-is-different-from-bot-api)
- [2. Session Security](#2-session-security)
- [3. Read-Only Wrapper](#3-read-only-wrapper)
- [4. Rate Limiting Strategy](#4-rate-limiting-strategy)
- [5. Telethon Method Inventory](#5-telethon-method-inventory)
- [6. Monitoring and Alerting](#6-monitoring-and-alerting)
- [7. Emergency Procedures](#7-emergency-procedures)

---

## 1. Why Telethon Is Different from Bot API

Telethon implements MTProto — the same binary protocol official Telegram clients use. Authenticating logs in as **your user account**, not a bot. The session file is equivalent to being logged into Telegram on another device.

| Aspect | Bot API | Telethon (MTProto) |
|--------|---------|----------------------------|
| **Identity** | Bot account | Your personal account |
| **Protocol** | HTTPS to `api.telegram.org` | MTProto binary to Telegram DCs |
| **Authentication** | Revocable bot token | Session file with auth keys |
| **Message access** | Only chats where bot is a member | Account chats (ingestion scope is configurable) |
| **Write capability** | Send as bot (labeled) | Send as YOU (indistinguishable) |
| **If credential leaks** | Revoke token, bot is isolated | Attacker **IS** you on Telegram |
| **Rate limits** | Liberal (bots expected automated) | Strict (human-like expected) |

A stolen session file has **no scope limitation** — unlike OAuth tokens, it's all-or-nothing: read all messages, send as you, delete conversations, modify profile, change 2FA, download all media.

MTProto connects directly to Telegram data centers (`149.154.160.0/20`, `91.108.0.0/16`) using its own encryption (AES-256-IGE), not TLS. This is why nftables rules allowlist DC IP ranges rather than a hostname.

---

## 2. Session Security

### What the Session File Contains

A `.session` file is an SQLite database containing the **authorization key** (256 bytes) — the critical secret for encrypting all communication with Telegram — plus DC info, entity cache, and update state. The auth key is the only security-critical piece.

### Encryption at Rest

The session file never exists on disk in plaintext. Encrypted using Fernet (AES-128-CBC + HMAC-SHA256) with the key stored in the system keychain.

```
Startup:  keychain → Fernet key → decrypt session → in-memory only → Telethon
Shutdown: disconnect → dereference in-memory session → nothing written to disk
```

Implementation: `src/shared/secrets.py` for encryption helpers and
`src/syncer/main.py` for runtime decryption to tmpfs. Key functions:

| Function | Purpose |
|----------|---------|
| `get_secret()` | Reads from systemd credentials or keychain |
| `decrypt_session_file()` | Decrypts the encrypted session bytes in memory |
| `encrypt_session_file()` | Encrypts a plaintext session file in place |

**Why Fernet**: Misuse-resistant authenticated encryption from Python's `cryptography` library. 128-bit keys are sufficient — the threat is offline file theft, not state-level cryptanalysis.

### File Permissions

```
/var/lib/tg-syncer/
└── tg_syncer_session.session.enc  # -rw------- (0600) tg-syncer:tg-syncer
```

The encryption key lives in the system keychain — never on disk or in env vars. Environment variables are visible via `/proc/<pid>/environ`, logged by crash reporters, and inherited by child processes.

### Session Rotation

Rotate every 90 days or after any suspected compromise. Use the built-in
session setup script to recreate and encrypt the session safely.

1. `sudo systemctl stop tg-syncer`
2. Back up current encrypted session:
   ```bash
   sudo cp /var/lib/tg-syncer/tg_syncer_session.session.enc \
            /var/lib/tg-syncer/tg_syncer_session.session.enc.bak.$(date +%Y%m%d)
   ```
3. Terminate old session in Telegram (Settings > Devices)
4. Recreate the session:
   ```bash
   sudo ./scripts/setup-telethon-session.sh
   ```
5. `sudo systemctl start tg-syncer`
6. Confirm old session no longer appears in Telegram Devices

---

## 3. Read-Only Wrapper

The `ReadOnlyTelegramClient` is the most important security control. It wraps `TelegramClient` with a strict **allowlist** of permitted methods.

### How It Works

```python
ALLOWED_METHODS: FrozenSet[str] = frozenset({
    # READ: get_messages, get_dialogs, get_entity, get_participants,
    #        get_me, iter_messages, iter_dialogs, download_profile_photo
    # LIFECYCLE: connect, disconnect, is_connected, start, run_until_disconnected
})

class ReadOnlyTelegramClient:
    def __getattribute__(self, name: str) -> Any:
        if name not in ALLOWED_METHODS:
            raise PermissionError(f"Method '{name}' blocked. Read-only mode.")
        return getattr(underlying_client, name)

    def __setattr__(self, name, value):  # Immutable
        raise PermissionError("Wrapper is immutable.")
```

Every blocked call is logged as a security event. Full implementation: `src/syncer/readonly_client.py`. Tests: `tests/test_readonly_client.py`.

### Why Allowlist, Not Blocklist

| Scenario | Blocklist | Allowlist |
|----------|-----------|-----------|
| New read method added to Telethon | Allowed (correct) | Blocked until reviewed (safe) |
| New write method added to Telethon | **Allowed (DANGEROUS)** | Blocked by default (safe) |
| Method renamed in Telethon | Old blocked, **new allowed** | Old allowed, new blocked (safe) |

With a blocklist, you race against Telethon's changelog. With an allowlist, **default is deny**.

### Residual Bypass Risk

The wrapper now keeps the underlying Telethon object outside instance attributes, so direct `client._client` extraction is blocked. Residual risk remains if an attacker can execute arbitrary Python in-process and introspect module internals. This control is still one layer in defense in depth; kernel/network/systemd isolation remain required.

---

## 4. Rate Limiting Strategy

Telegram monitors for bot-like behavior and can temporarily rate-limit (`FloodWaitError`), permanently restrict, or ban accounts. Since we use a personal account, access patterns must look human-like.

Implementation: `src/syncer/main.py` (`rate_limit_delay` helper).

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Min call interval | 2.0s | Base delay between API calls |
| Jitter | 0.1–1.5s | Human-like randomness |
| Max concurrent calls | 1 | Sequential access pattern |
| Sync interval | 300s (5 min) | Gap between full sync cycles |
| Backoff multiplier | 1.5x on `FloodWaitError` | Exponential backoff, capped at 1 hour |

### Telegram's Known Thresholds

| Operation | Observed Threshold | Our Limit | Safety Margin |
|-----------|-------------------|-----------|---------------|
| Requests per second | ~20-30 | 0.5 (one per 2s) | 40-60x under |
| `get_dialogs` calls | ~20-30/min | 1/5min | 100-150x under |
| `get_messages` across chats | ~30-40/min | ~12/min | 2.5-3x under |

### Sync Cycle Pattern

```
t=0:00  get_dialogs()
t=0:02  get_messages(chat_1)     ← 2+ seconds between each
t=0:04  get_messages(chat_2)
...     (~15 active chats)
t=0:30  Sync complete
t=5:00  Next sync starts
```

Configurable via `config/settings.toml` under `[syncer.rate_limits]`.

### Human-Like Patterns

- Random jitter on every delay
- Variable batch sizes (50-100 messages)
- Sequential chat access (not parallel)
- Skip chats with no new messages since last sync
- Always respect `FloodWaitError` wait period + 10% buffer

---

## 5. Telethon Method Inventory

Complete categorization of `TelegramClient` methods by status and risk.

### ALLOWED — Read Operations

| Method | Description |
|--------|-------------|
| `get_messages` | Fetch messages from a chat |
| `get_dialogs` | List all conversations |
| `get_entity` | Resolve user/chat/channel by ID |
| `get_participants` | List group/channel members |
| `get_me` | Get authenticated user's info |
| `iter_messages` | Async iterator over messages |
| `iter_dialogs` | Async iterator over dialogs |
| `download_profile_photo` | Download profile picture |

### ALLOWED — Lifecycle Operations

| Method | Description |
|--------|-------------|
| `connect` | Establish MTProto connection |
| `disconnect` | Close MTProto connection |
| `is_connected` | Check connection status |
| `start` | Connect and verify authentication |
| `run_until_disconnected` | Block until disconnect |

### BLOCKED — Write Operations

| Method | Risk | Severity |
|--------|------|----------|
| `send_message` | Impersonation, spam | **CRITICAL** |
| `edit_message` | Content tampering | **CRITICAL** |
| `delete_messages` | Evidence destruction | **CRITICAL** |
| `forward_messages` | Data exfiltration | **CRITICAL** |
| `send_file` / `send_photo` | Impersonation, data exfil | **CRITICAL** |
| `send_read_acknowledge` | Privacy leak | **MEDIUM** |

### BLOCKED — Admin Operations

| Method | Risk | Severity |
|--------|------|----------|
| `kick_participant` | Abuse of admin power | **HIGH** |
| `edit_permissions` / `edit_admin` | Privilege escalation | **HIGH** / **CRITICAL** |
| `pin_message` / `unpin_message` | Disruption | **MEDIUM** / **LOW** |
| `create_channel` | Account abuse | **MEDIUM** |
| `delete_dialog` | Data destruction | **CRITICAL** |

### BLOCKED — Account Operations

| Method | Risk | Severity |
|--------|------|----------|
| `update_profile` / `update_username` | Identity manipulation | **HIGH** |
| `edit_2fa` | Account takeover | **CRITICAL** |
| `log_out` | DoS against syncer | **MEDIUM** |
| `sign_in` / `sign_up` | Should not be called in operation | **HIGH** / **LOW** |
| `edit_folder` | Disruption | **LOW** |

---

## 6. Monitoring and Alerting

Every Telethon API call is logged as structured JSON (JSONL) to `/var/log/tg-assistant/telethon-audit.jsonl`. Implementation: `src/syncer/audit.py`.

Each entry records: `timestamp`, `method`, `chat_id`, `status` (success/error/blocked/flood_wait), `duration_ms`, and metadata.

```bash
# Query examples
jq 'select(.status == "blocked")' telethon-audit.jsonl         # Security events
jq 'select(.status == "flood_wait")' telethon-audit.jsonl       # Rate limit hits
jq -r '.chat_id' telethon-audit.jsonl | sort | uniq -c | sort -rn | head -20  # Top chats
```

### Alert Conditions

| Event | Severity | Action |
|-------|----------|--------|
| Blocked method attempt | **CRITICAL** | Immediate alert — bug or compromised dependency |
| `FloodWaitError` | **WARNING** | Log + backoff; investigate if >3/hour |
| Persistent connection failure (>10 min) | **WARNING** | Alert |
| Session file hash mismatch | **CRITICAL** | Halt syncer immediately |
| Session file permissions changed | **CRITICAL** | Halt syncer |

Alerts go to `/var/log/tg-assistant/security-alerts.log` and systemd journal (CRIT level). Session integrity is checked at startup and periodically during operation.

---

## 7. Emergency Procedures

### Suspected Session Theft

**Indicators**: Unexpected "new login" notification, unfamiliar session in Devices, messages you didn't send.

1. **Terminate sessions from Telegram** (Settings > Devices) — most important step
2. `sudo systemctl stop tg-syncer`
3. Enable 2FA if not set
4. Preserve evidence: `sudo cp -a /var/log/tg-assistant/ /root/incident-$(date +%Y%m%d)/`
5. Rotate session via `scripts/setup-telethon-session.sh`
6. Review audit logs: `jq 'select(.status == "blocked")' telethon-audit.jsonl`

### Active Account Compromise

**Indicators**: Messages from your account you didn't write, profile changes, contacts removed.

1. **Terminate ALL other sessions** from your phone (only trusted device)
2. Change 2FA password
3. `sudo systemctl stop tg-syncer`
4. If Pi was compromised: rotate ALL credentials (session, bot token, Claude API key, Telegram API ID/hash, Fernet key)

### Repeated FloodWaitErrors

Not a security incident, but can lead to account restriction.

1. Increase `sync_interval_seconds` (300 → 600) and `min_call_interval_seconds` (2.0 → 3.0)
2. Reduce chats synced per cycle
3. If persistent: stop syncer for 2-4 hours to let rate limit window reset

### Quick Reference Commands

```bash
sudo systemctl stop tg-syncer tg-querybot                        # Stop everything
tail -50 /var/log/tg-assistant/security-alerts.log                # Recent alerts
tail -100 /var/log/tg-assistant/telethon-audit.jsonl | jq .       # Recent audit
stat -c '%a %U:%G %n' /var/lib/tg-syncer/tg_syncer_session.session.enc # Check permissions
```

---

## Summary

| Control | Type | Protects Against |
|---------|------|-----------------|
| Session encryption (Fernet) | Preventive | Session theft from disk |
| File permissions (0600) | Preventive | Cross-user session access |
| Read-only wrapper (allowlist) | Preventive | Accidental/malicious writes |
| Rate limiter | Preventive | Account bans |
| Session integrity hash | Detective | File tampering |
| Audit logging | Detective | Post-incident forensics |
| Alert system | Detective | Real-time compromise detection |
| Session rotation | Corrective | Limit exposure window |

Every control is one layer. No single control is sufficient. Together they form the defense-in-depth model described in [SECURITY_MODEL.md](SECURITY_MODEL.md).
