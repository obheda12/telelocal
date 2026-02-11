# Telegram Personal Assistant

A defense-in-depth personal assistant that syncs ALL your Telegram messages to a local database and lets you query them through a private bot powered by Claude. Deployed on a Raspberry Pi for physical control over your data.

## Why This Exists

Managing many Telegram groups, channels, and conversations means important messages get buried. This system gives you a single interface to search and analyze your entire Telegram history:

> "What did Alice say yesterday about the product launch?"
> "Summarize the discussion in the engineering group this week"
> "Find all messages mentioning the budget deadline"

The previous architecture (IronClaw + Bot API) required adding a bot to every chat. This was impractical at scale. The new architecture uses Telethon (MTProto User API) to sync messages from ALL your chats — groups, channels, DMs — without requiring bot membership.

### Why IronClaw Was Removed

IronClaw (Rust WASM runtime) was the core of the previous architecture. It doesn't fit the new design:

| IronClaw Feature | New Equivalent | Why IronClaw Doesn't Fit |
|---|---|---|
| WASM Sandbox | Python read-only wrapper around Telethon | Telethon is Python — can't run in WASM |
| LLM Orchestration | Claude API (cloud) | No local LLM to orchestrate |
| Host Boundary Layer | Process isolation + nftables | Different data flow, different trust boundaries |
| Credential Injection | System keychain + env injection via systemd | Telethon session != bot token; different credential model |
| HTTP Allowlist | nftables kernel firewall | More robust than application-level allowlist |

What carries over: the defense-in-depth *philosophy*, threat modeling approach, systemd hardening patterns, and documentation standards.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Security Model](#security-model)
- [Why Raspberry Pi](#why-raspberry-pi)
- [Telethon vs Bot API](#telethon-vs-bot-api)
- [Threat Analysis](#threat-analysis)
- [Implementation Details](#implementation-details)
- [Deployment Guide](#deployment-guide)
- [Verification Procedures](#verification-procedures)
- [Incident Response](#incident-response)
- [Known Security Limitations](#known-security-limitations)
- [Future Hardening Path](#future-hardening-path)

---

## Architecture Overview

Three process-isolated services run on the Raspberry Pi:

```mermaid
flowchart TB
    subgraph Pi["Raspberry Pi"]
        direction TB

        subgraph Services["Process-Isolated Services"]
            direction LR
            Syncer["**TG Syncer**<br/>(Telethon MTProto)<br/>READ-ONLY User API"]
            QueryBot["**Query Bot**<br/>(Bot API + Claude API)<br/>Responds to owner only"]
            DB[("**PostgreSQL**<br/>+ pgvector<br/>Messages / Embeds / Audit")]
        end

        subgraph Firewall["nftables (kernel-level)"]
            direction LR
            FW1["tg-syncer → TG MTProto only"]
            FW2["tg-querybot → TG Bot API +<br/>api.anthropic.com only"]
        end

        subgraph Keychain["System Keychain (AES-256-GCM)"]
            direction LR
            K1["Telethon session key"]
            K2["Bot token"]
            K3["Claude API key"]
            K4["DB credentials"]
        end
    end

    Syncer --> DB
    QueryBot <--> DB
```

### Data Flow — Message Sync

```mermaid
sequenceDiagram
    autonumber
    participant TG as Telegram<br/>(all chats)
    participant Syncer as TG Syncer<br/>(Telethon)
    participant DB as PostgreSQL<br/>+ pgvector
    participant Audit as Audit Log

    loop Every sync interval
        Syncer->>TG: MTProto: get_dialogs / iter_messages
        TG-->>Syncer: Messages from all chats
        Syncer->>Syncer: Sanitize content
        Syncer->>DB: INSERT messages + embeddings
        Syncer->>Audit: Log API call + result
    end
```

### Data Flow — User Query

```mermaid
sequenceDiagram
    autonumber
    participant User as You (Telegram)
    participant Bot as Query Bot
    participant DB as PostgreSQL
    participant Claude as Claude API

    User->>Bot: "What did Alice say about X?"
    Bot->>Bot: Verify sender == owner_id

    Bot->>DB: FTS + vector search
    DB-->>Bot: Top-K relevant messages

    Bot->>Claude: Context (relevant msgs only)<br/>+ user question
    Claude-->>Bot: Analysis / summary

    Bot->>User: Response
    Bot->>DB: Audit log entry
```

---

## Security Model

### Defense-in-Depth Layers

| Layer | Protection | Bypass Requires |
|-------|-----------|-----------------|
| **Physical** | Pi in your home | Physical intrusion |
| **Systemd** | Per-service hardening, dedicated users | Kernel exploit |
| **Network (nftables)** | Per-process IP allowlists at kernel level | Kernel exploit |
| **Process Isolation** | Separate processes, users, DB roles | Privilege escalation |
| **Read-Only Wrapper** | Telethon allowlist pattern (not blocklist) | Python runtime exploit |
| **Credential Isolation** | System keychain, never in env/files | Keychain compromise |
| **Audit** | All API calls logged, tamper-evident | Log deletion (mitigated by append-only) |

### Process Isolation Model

Each service runs as a dedicated system user with minimal permissions:

| Service | System User | DB Role | Network Access |
|---------|-------------|---------|----------------|
| TG Syncer | `tg-syncer` | `syncer_role` (INSERT + SELECT on messages) | Telegram MTProto IPs only |
| Query Bot | `tg-querybot` | `querybot_role` (SELECT only on messages) | `api.telegram.org` + `api.anthropic.com` |
| PostgreSQL | `postgres` | N/A | Localhost only |

### Read-Only Enforcement (Telethon)

The syncer wraps Telethon in `ReadOnlyTelegramClient` — an **allowlist** (not blocklist) of permitted methods. Any method not explicitly listed raises `PermissionError`. New Telethon methods are blocked by default.

Details: [`tg-assistant/docs/TELETHON_HARDENING.md`](tg-assistant/docs/TELETHON_HARDENING.md)

---

## Why Raspberry Pi

| Factor | Raspberry Pi | Cloud VPS | Winner |
|--------|-------------|-----------|--------|
| **Physical access** | Only you | Provider employees, law enforcement | Pi |
| **Memory inspection** | Requires physical presence | Provider can snapshot at will | Pi |
| **Side-channel attacks** | None (dedicated hardware) | Spectre, Meltdown, L1TF | Pi |
| **Legal jurisdiction** | Your home jurisdiction only | Provider's + data center location | Pi |
| **Cost** | ~$80 one-time | $5-20/month ongoing | Pi |
| **Uptime** | Depends on your power/internet | 99.9%+ SLA | Cloud |
| **Maintenance** | You handle everything | Managed options available | Cloud |

---

## Telethon vs Bot API

| Aspect | Bot API (old) | Telethon / MTProto (new) |
|--------|---------------|--------------------------|
| **Message access** | Only chats where bot is added | ALL user's chats, groups, channels |
| **Authentication** | Bot token | User session (phone + 2FA) |
| **Session risk** | Token leak = bot compromise | Session leak = **full account compromise** |
| **Read-only enforcement** | Config-level method blocking | Code-level allowlist wrapper |

A stolen Telethon session grants full account access (read, write, delete, change settings), not just bot control. This is why session encryption, the read-only wrapper, and nftables are essential.

Full comparison: [`tg-assistant/docs/TELETHON_HARDENING.md`](tg-assistant/docs/TELETHON_HARDENING.md)

---

## Threat Analysis

### Threats Mitigated

| Threat | Attack Vector | Mitigation | Residual Risk |
|--------|---------------|------------|---------------|
| **Session theft** | File system access to `.session` | Encrypted at rest (Fernet), 0600 permissions, dedicated user | Keychain compromise required |
| **Unintended writes** | Telethon writes on user's behalf | Read-only wrapper (allowlist pattern) | Python runtime exploit |
| **Data exfiltration** | Syncer sends data to external host | nftables restricts to Telegram MTProto IPs only | Kernel exploit |
| **Claude API key theft** | Bot process compromised | Keychain storage, nftables blocks all except `api.anthropic.com` | Keychain compromise |
| **Unauthorized bot access** | Attacker messages the bot | Owner-only check (hardcoded user ID), all others silently ignored | Telegram user ID spoof (not possible) |
| **Prompt injection** | Malicious message in synced data | Data minimization to Claude, system prompt hardening | LLM manipulation (medium) |
| **Account ban** | Bot-like behavior triggers Telegram | Conservative rate limits, human-like access patterns | Telegram policy change |
| **Privilege escalation** | Exploit in any service | `NoNewPrivileges`, dropped capabilities, syscall filtering | Kernel exploit |

### Attack Path Analysis

```mermaid
flowchart TD
    Attack["Attacker Goal:<br/>Access user's messages"]

    Attack --> A1["Steal Telethon Session"]
    Attack --> A2["Prompt Injection via Chat"]
    Attack --> A3["Compromise Query Bot"]

    A1 --> S1{"Encrypted at rest?"}
    S1 -->|"Yes"| S2{"Keychain access?"}
    S2 -->|"Blocked (dedicated user)"| Block1["BLOCKED"]
    S2 -->|"Privilege escalation"| S3{"Kernel exploit?"}
    S3 -->|"Required"| Block2["BLOCKED<br/>(defense in depth)"]

    A2 --> P1["Malicious message synced"]
    P1 --> P2["User queries about it"]
    P2 --> P3{"Claude influenced?"}
    P3 -->|"No"| Safe1["Safe response"]
    P3 -->|"Yes"| P4["Bad summary/analysis"]
    P4 --> P5["No write capability"]

    A3 --> B1{"Network access?"}
    B1 -->|"nftables: only TG + Anthropic"| Block3["BLOCKED"]

    style Block1 fill:#c8e6c9
    style Block2 fill:#c8e6c9
    style Block3 fill:#c8e6c9
    style Safe1 fill:#c8e6c9
    style P4 fill:#fff3e0
```

---

## Implementation Details

### File Structure

```
tg-assistant/
├── config/
│   ├── settings.toml              # All service configuration
│   └── system_prompt.md           # Claude API system prompt
├── src/
│   ├── syncer/
│   │   ├── __init__.py
│   │   ├── main.py                # Syncer entry point
│   │   ├── readonly_client.py     # Read-only Telethon wrapper
│   │   ├── message_store.py       # PostgreSQL message storage
│   │   └── embeddings.py          # Embedding generation
│   ├── querybot/
│   │   ├── __init__.py
│   │   ├── main.py                # Bot entry point
│   │   ├── search.py              # FTS + vector search
│   │   ├── llm.py                 # Claude API integration
│   │   └── handlers.py            # Bot command/message handlers
│   └── shared/
│       ├── __init__.py
│       ├── db.py                  # Database connection helpers
│       ├── secrets.py             # Keychain integration
│       └── audit.py               # Audit logging
├── scripts/
│   ├── setup-raspberry-pi.sh      # Installation script
│   ├── setup-telethon-session.sh  # Guided session creation
│   └── monitor-network.sh         # Traffic verification
├── systemd/
│   ├── tg-syncer.service          # Syncer service (hardened)
│   └── tg-querybot.service        # Query bot service (hardened)
├── nftables/
│   └── tg-assistant-firewall.conf # Per-process network rules
├── tests/
│   ├── security-verification.sh   # Automated security tests
│   ├── test_readonly_client.py    # Unit tests for read-only wrapper
│   └── prompt-injection-tests.md  # Manual test cases
├── docs/
│   ├── QUICKSTART.md              # Deployment checklist
│   ├── SECURITY_MODEL.md          # Detailed security documentation
│   ├── TELETHON_HARDENING.md      # Telethon-specific security guide
│   └── FUTURE_STATE_PLAN.md       # Hardening roadmap
└── requirements.txt               # Python dependencies
```

### Database Schema

```sql
-- Messages: synced from all Telegram chats
CREATE TABLE messages (
    id              BIGSERIAL PRIMARY KEY,
    telegram_msg_id BIGINT NOT NULL,
    chat_id         BIGINT NOT NULL,
    chat_title      VARCHAR(255),
    sender_id       BIGINT,
    sender_name     VARCHAR(255),
    content         TEXT NOT NULL,
    message_type    VARCHAR(50) DEFAULT 'text',
    reply_to_msg_id BIGINT,
    timestamp       TIMESTAMPTZ NOT NULL,
    synced_at       TIMESTAMPTZ DEFAULT NOW(),
    embedding       vector(1024),
    UNIQUE(telegram_msg_id, chat_id)
);

-- Role separation: syncer can write, querybot can only read
CREATE ROLE syncer_role;
GRANT INSERT, SELECT ON messages, chats TO syncer_role;

CREATE ROLE querybot_role;
GRANT SELECT ON messages, chats TO querybot_role;
```

### Embedding Strategy

| Option | Model | Dimensions | Cost | Latency |
|--------|-------|-----------|------|---------|
| **Primary** | Voyage-3 (via API) | 1024 | Per-token | ~100ms |
| **Fallback** | all-MiniLM-L6-v2 (local) | 384 | Free | ~50ms on Pi |

Embeddings are generated during sync and stored in PostgreSQL with pgvector for cosine similarity search.

---

## Deployment Guide

### Prerequisites

| Requirement | Specification |
|-------------|---------------|
| Hardware | Raspberry Pi 4 (4GB+) or Pi 5 |
| OS | Raspberry Pi OS (64-bit) or Ubuntu 22.04+ ARM64 |
| Storage | 32GB+ SD card or USB SSD (recommended) |
| Network | Ethernet (recommended) or WiFi |
| Accounts | Telegram account, Anthropic API key |

### Quick Start

```bash
# 1. Clone and run setup
git clone <your-repo> && cd tg-assistant
./scripts/setup-raspberry-pi.sh

# 2. Create Telethon session (interactive — requires phone + 2FA)
./scripts/setup-telethon-session.sh

# 3. Create Telegram bot via @BotFather, add token to keychain

# 4. Add credentials
# (guided by setup script)

# 5. Verify security
./tests/security-verification.sh

# 6. Start services
sudo systemctl enable tg-syncer tg-querybot
sudo systemctl start tg-syncer tg-querybot
```

Full deployment guide: [`tg-assistant/docs/QUICKSTART.md`](tg-assistant/docs/QUICKSTART.md)

---

## Verification Procedures

### Weekly Security Checklist

```bash
# 1. Review audit logs for anomalies
grep -i "injection\|blocked\|error\|denied" /var/log/tg-assistant/audit.log | tail -100

# 2. Verify no unexpected network connections
sudo ./tg-assistant/scripts/monitor-network.sh 30

# 3. Check service health
systemctl status tg-syncer tg-querybot

# 4. Verify Telethon session hasn't been exported
ls -la /home/tg-syncer/.telethon/  # Should only have encrypted .session

# 5. Check disk space
df -h /var/log/tg-assistant
```

---

## Incident Response

If you suspect a compromise:

1. **Stop all services** — `sudo systemctl stop tg-syncer tg-querybot`
2. **Terminate Telethon session** — Log into Telegram, Settings > Devices, terminate the session
3. **Preserve evidence** — Copy logs and config before making changes
4. **Rotate ALL credentials** — Telethon session, bot token, Claude API key, DB passwords
5. **Review audit logs** — Look for unauthorized API calls or query patterns
6. **Verify and restart** — Run `./tests/security-verification.sh`, then restart

**Critical**: If the Telethon session file was stolen, the attacker has full account access. Terminate the session immediately from another Telegram client.

---

## Known Security Limitations

| # | Limitation | Severity |
|---|------------|----------|
| 1 | Telethon session = full account access if stolen | **CRITICAL** |
| 2 | LLM reasoning manipulation via prompt injection | **MEDIUM** |
| 3 | Claude API sees message content (cloud) | **MEDIUM** |
| 4 | Python runtime is less sandboxed than WASM | **LOW** |
| 5 | Supply chain (Python packages) | **LOW** |

Full threat model with risk matrix and accepted risks: [`tg-assistant/docs/SECURITY_MODEL.md`](tg-assistant/docs/SECURITY_MODEL.md)

Hardening roadmap: [`tg-assistant/docs/FUTURE_STATE_PLAN.md`](tg-assistant/docs/FUTURE_STATE_PLAN.md)

---

## License

MIT License. For personal and educational use.

**Telethon**: MIT License — [github.com/LonamiWebs/Telethon](https://github.com/LonamiWebs/Telethon)
**python-telegram-bot**: LGPL-3.0 — [github.com/python-telegram-bot/python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot)
**Claude API**: Subject to [Anthropic's Terms of Service](https://www.anthropic.com/terms)
