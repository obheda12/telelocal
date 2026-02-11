# Telegram Personal Assistant

A defense-in-depth personal assistant that syncs ALL your Telegram messages to a local database and lets you query them through a private bot powered by Claude. Deployed on a Raspberry Pi for physical control over your data.

## Why This Exists

Managing many Telegram groups, channels, and conversations means important messages get buried. This system gives you a single interface to search and analyze your entire Telegram history:

> "What did Alice say yesterday about the product launch?"
> "Summarize the discussion in the engineering group this week"
> "Find all messages mentioning the budget deadline"

The architecture uses Telethon (MTProto User API) to sync messages from ALL your chats — groups, channels, DMs — without requiring bot membership in each chat.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture Overview](#architecture-overview)
- [Security Model](#security-model)
- [Telethon vs Bot API](#telethon-vs-bot-api)
- [Threat Analysis](#threat-analysis)
- [Pi vs VPS](#pi-vs-vps)
- [Implementation Details](#implementation-details)
- [Deployment Guide](#deployment-guide)
- [Verification Procedures](#verification-procedures)
- [Incident Response](#incident-response)
- [Known Security Limitations](#known-security-limitations)

---

## How It Works

Two independent processes run on your Raspberry Pi:

1. **Background sync** — `tg-syncer` continuously pulls messages from all your Telegram chats and stores them locally. You never interact with it.
2. **On-demand query** — When you message the bot, `tg-querybot` searches the local database, sends the relevant messages to Claude, and returns the answer.

### Background: Message Sync

```mermaid
sequenceDiagram
    box rgb(255,243,224) Internet
        participant TG as Telegram Servers
    end
    box rgb(232,245,233) Raspberry Pi
        participant Syncer as tg-syncer (read-only)
        participant DB as PostgreSQL
    end

    loop Every 5 minutes
        Syncer->>TG: Fetch new messages (MTProto)
        TG-->>Syncer: Messages from all chats
        Syncer->>DB: Store messages + embeddings
    end
```

The syncer uses a **read-only wrapper** around Telethon — only 15 explicitly allowed read methods work. All write methods (`send_message`, `delete_messages`, etc.) raise `PermissionError`.

### Your Query Flow

```mermaid
sequenceDiagram
    autonumber
    box rgb(230,245,255) Your Device
        participant You as You (Telegram App)
    end
    box rgb(255,243,224) Internet
        participant TG as Telegram Servers
    end
    box rgb(232,245,233) Raspberry Pi (Trusted Zone)
        participant Bot as tg-querybot
        participant DB as PostgreSQL
    end
    box rgb(255,235,238) Cloud
        participant Claude as Claude API
    end

    You->>TG: "What did Alice say about the launch?"
    TG->>Bot: Deliver message (Bot API)
    Bot->>Bot: Verify sender == owner_id
    Bot->>DB: Full-text + vector search
    DB-->>Bot: Top-K relevant messages
    Bot->>Claude: Top-K context + your question
    Claude-->>Bot: Analysis / summary
    Bot->>TG: Send response
    TG->>You: "Alice said X about Y..."
```

**Trust boundaries**: Your Raspberry Pi (green) is the only trusted zone. Telegram (orange) relays messages but has no access to your database or credentials. The Claude API (red) receives only the top-K relevant messages per query — not the full database. Each process is restricted by kernel-level nftables rules to only its specific allowed network destinations.

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

## Telethon vs Bot API

| Aspect | Bot API | Telethon / MTProto |
|--------|---------|-------------------|
| **Message access** | Only chats where bot is added | ALL user's chats, groups, channels |
| **Authentication** | Bot token | User session (phone + 2FA) |
| **Session risk** | Token leak = bot compromise | Session leak = **full account compromise** |
| **Read-only enforcement** | Config-level method blocking | Code-level allowlist wrapper |

A stolen Telethon session grants full account access (read, write, delete, change settings), not just bot control. This is why session encryption, the read-only wrapper, and nftables are essential.

Full comparison: [`tg-assistant/docs/TELETHON_HARDENING.md`](tg-assistant/docs/TELETHON_HARDENING.md)

---

## Threat Analysis

### Threat Summary

| Threat | Severity | Attack Vector | Mitigation | Residual Risk |
|--------|----------|---------------|------------|---------------|
| **Session theft** | **CRITICAL** | File system access to `.session` | Fernet encryption at rest, `0600` perms, dedicated user, keychain | Requires privilege escalation + keychain compromise |
| **Unintended writes** | **CRITICAL** | Telethon writes on user's behalf | Read-only allowlist wrapper (15 methods, default-deny) | Python runtime exploit to bypass wrapper |
| **Data exfiltration** | **HIGH** | Compromised process phones home | Per-UID nftables: syncer→TG only, querybot→TG+Anthropic only | Kernel exploit to bypass netfilter |
| **Unauthorized bot access** | **HIGH** | Attacker messages the bot | Hardcoded `owner_id` check, all others silently ignored | Telegram user ID spoof (not possible) |
| **Privilege escalation** | **HIGH** | Exploit in any service pivots to others | Separate users, `NoNewPrivileges`, dropped capabilities, syscall filter | Kernel exploit |
| **Prompt injection** | **MEDIUM** | Malicious message in synced data | Trust hierarchy in system prompt, data minimization, no write path | LLM manipulation (misleading summary) |
| **Account ban** | **MEDIUM** | Bot-like behavior triggers Telegram | Conservative rate limits, human-like patterns, exponential backoff | Telegram policy change |
| **Supply chain** | **MEDIUM** | Compromised Python dependency | Pinned versions, nftables limits blast radius, systemd confinement | In-memory session accessible to compromised syncer |

### Key Threat Details

**Session theft** — A Telethon session is equivalent to being logged into your Telegram on another device. If stolen, an attacker gets full account access: read, write, delete, change settings. The session file is Fernet-encrypted (AES-128-CBC + HMAC-SHA256) with the key in the system keychain. The encrypted file is `0600`, owned by a dedicated `tg-syncer` user. Plaintext only exists in memory — never on disk. An attacker would need to escalate to the `tg-syncer` user AND access the keychain, both blocked by systemd hardening.

**Unintended writes** — Telethon's `TelegramClient` has full read/write access to your account. The syncer wraps it in `ReadOnlyTelegramClient` using an **allowlist** — only 15 read methods are permitted, everything else raises `PermissionError`. This is an allowlist, not a blocklist: new Telethon methods in future updates are blocked by default until reviewed.

**Data exfiltration** — Per-UID nftables rules restrict each process to specific IPs at the kernel level. The syncer can only reach Telegram MTProto data centers (`149.154.160.0/20`, `91.108.0.0/16`). The querybot can only reach `api.telegram.org` and `api.anthropic.com`. All other outbound traffic — including to LAN hosts — is dropped. Even with code execution, a compromised process cannot phone home.

**Prompt injection** — Malicious messages in synced chats could contain adversarial instructions that Claude sees as context. The architecture constrains the blast radius: the system prompt treats message content as untrusted, only top-K messages go to Claude (not the full DB), and there is no write path — even a manipulated Claude cannot send messages, access files, or modify the database. Worst outcome: a misleading summary shown to the owner.

### Attack Path Analysis

The diagram below shows the three primary attack vectors and how defense-in-depth layers block them. For comprehensive attack trees covering supply chain, physical access, and lateral movement, see [SECURITY_MODEL.md](tg-assistant/docs/SECURITY_MODEL.md#10-attack-trees).

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

## Pi vs VPS

| Factor | Raspberry Pi | Cloud VPS | Security Consideration |
|--------|-------------|-----------|------------------------|
| **Physical access** | Only you (requires home intrusion) | Provider employees, law enforcement, datacenter staff | Pi: No third-party physical access. VPS: Trust provider's access controls and legal jurisdiction |
| **Memory inspection** | Requires physical device access + powered on | Provider can snapshot VM memory anytime | Pi: Memory inaccessible without physical presence. VPS: Hypervisor has full memory access |
| **Side-channel attacks** | Dedicated hardware (no shared CPU) | Spectre, Meltdown, L1TF, cross-VM cache timing | Pi: No cross-tenant attacks possible. VPS: Mitigations rely on hypervisor patches |
| **Legal jurisdiction** | Your home jurisdiction only | Provider's ToS + datacenter location + user location | Pi: Single legal framework. VPS: Multiple jurisdictions may apply |
| **Network isolation** | Your home network perimeter | Shared datacenter network with provider visibility | Pi: Network traffic only visible to your ISP. VPS: Provider can inspect all traffic |

**Choose Raspberry Pi if** your primary threats are state-level surveillance, cloud provider data access, or legal subpoenas to cloud infrastructure. **Choose Cloud VPS if** your primary threats are physical theft, home intrusion, or local law enforcement.

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
│   └── TELETHON_HARDENING.md      # Telethon-specific security guide
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
    embedding       vector(384),
    UNIQUE(telegram_msg_id, chat_id)
);

-- Role separation: syncer can write, querybot can only read
CREATE ROLE syncer_role;
GRANT INSERT, SELECT ON messages, chats TO syncer_role;

CREATE ROLE querybot_role;
GRANT SELECT ON messages, chats TO querybot_role;
```

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
| 4 | Python runtime relies on process isolation, not memory sandbox | **LOW** |
| 5 | Supply chain (Python packages) | **LOW** |

Full threat model with risk matrix and accepted risks: [`tg-assistant/docs/SECURITY_MODEL.md`](tg-assistant/docs/SECURITY_MODEL.md)

---

## License

MIT License. For personal and educational use.

**Telethon**: MIT License — [github.com/LonamiWebs/Telethon](https://github.com/LonamiWebs/Telethon)
**python-telegram-bot**: LGPL-3.0 — [github.com/python-telegram-bot/python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot)
**Claude API**: Subject to [Anthropic's Terms of Service](https://www.anthropic.com/terms)
