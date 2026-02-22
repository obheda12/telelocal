# Local First Telegram Personal Assistant

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
- [Implementation Details](#implementation-details) (includes [Codebase Size](#codebase-size))
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

The syncer paginates message history to avoid gaps: on the first sync of a chat it walks back through history (bounded by `max_history_days` if set), and on subsequent syncs it fetches **all** messages newer than the last stored ID — even if more than one batch arrives between cycles.

Performance defaults:
- No per-pass pre-scan by default (`enable_prescan_progress = false`) to avoid one extra API call per chat.
- `store_raw_json = false` by default to reduce ingest CPU and database bloat.
- Active dialogs are synced in most-recent-first order so fresh chats become queryable first.

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
        participant Haiku as Claude Haiku
        participant Sonnet as Claude Sonnet
    end

    You->>TG: "What did Alice say about the launch?"
    TG->>Bot: Deliver message (Bot API)
    Bot->>Bot: Verify sender == owner_id
    Bot->>DB: Fetch chat list (cached)
    Bot->>Haiku: Question + chat list → extract intent
    Haiku-->>Bot: {chat_ids, sender, time_range, keywords}
    Bot->>DB: Filtered FTS (scoped to matched chats)
    DB-->>Bot: Top-K relevant messages
    Bot->>Sonnet: Top-K context + your question
    Sonnet-->>Bot: Analysis / summary
    Bot->>TG: Send response
    TG->>You: "Alice said X about Y..."
```

**Trust boundaries**: Your Raspberry Pi (green) is the only trusted zone. Telegram (orange) relays messages but has no access to your database or credentials. The Claude API (red) receives only the top-K relevant messages per query — not the full database. Intent extraction uses Haiku (fast/cheap) with just your question and chat names; the main synthesis uses Sonnet with message context. Each process is restricted by kernel-level nftables rules to only its specific allowed network destinations.

### Query Intent Extraction

When you have 100+ group chats (often named like `TeamName <> YourCompany`), searching the entire database for every query would return noisy, irrelevant results. The querybot solves this with a two-stage pipeline:

```mermaid
flowchart LR
    Q["Your question"]
    Q --> IE["**Intent Extraction**<br/>(Haiku — fast/cheap)"]

    CL["Chat list<br/>from DB (cached)"]
    CL --> IE

    IE --> F{"Structured filters"}
    F --> |"chat_ids"| FS
    F --> |"sender_name"| FS
    F --> |"days_back"| FS
    F --> |"search_terms"| FS

    FS["**Filtered FTS**<br/>(PostgreSQL)"] --> R["Scoped results<br/>grouped by chat"]
    R --> S["**Synthesis**<br/>(Sonnet)"]
    S --> A["Your answer"]
```

| You ask | Intent extracted | What gets searched |
|---------|----------------|--------------------|
| "What did the Acme team say about pricing?" | `chat_ids=[Acme <>...]`, `search_terms="pricing"` | Only the Acme chat, FTS for "pricing" |
| "Summarize yesterday's engineering chat" | `chat_ids=[Engineering <>...]`, `days_back=2` | Last 2 days in Engineering, no keyword filter (browse mode) |
| "What did Alice say about deployment?" | `sender_name="Alice"`, `search_terms="deployment"` | All chats, filtered to Alice's messages about deployment |
| "Find messages about the budget deadline" | `search_terms="budget deadline"` | All chats, keyword search only |

The intent extraction runs on **Haiku** (~$0.002/query) and only sees your question + chat names — never message content. The main synthesis runs on **Sonnet** with the filtered results.

If the filtered search returns nothing (e.g., Haiku misidentified the chat), the system falls back to unfiltered full-text search across all chats.

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

        subgraph Keychain["systemd-creds (AES-256-GCM, encrypted at rest)"]
            direction LR
            K1["Telethon session key<br/>(tg-syncer only)"]
            K2["Bot token<br/>(tg-querybot only)"]
            K3["Claude API key<br/>(tg-querybot only)"]
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
| **Credential Isolation** | systemd-creds encrypt (AES-256-GCM), per-service credentials, peer auth | Root + machine key extraction |
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
| **Credential exposure** | **CRITICAL** | Physical theft, privilege escalation, memory dump | systemd-creds encrypt (AES-256-GCM), per-service isolation, peer auth, no plaintext on disk | Kernel exploit + machine key extraction |
| **Prompt injection** | **MEDIUM** | Malicious message in synced data | Trust hierarchy in system prompt, data minimization, no write path | LLM manipulation (misleading summary) |
| **Account ban** | **MEDIUM** | Bot-like behavior triggers Telegram | Conservative rate limits, human-like patterns, exponential backoff | Telegram policy change |
| **Supply chain** | **MEDIUM** | Compromised Python dependency | Pinned versions, nftables limits blast radius, systemd confinement | In-memory session accessible to compromised syncer |

### Key Threat Details

**Session theft** — A Telethon session is equivalent to being logged into your Telegram on another device. If stolen, an attacker gets full account access: read, write, delete, change settings. The session file is Fernet-encrypted (AES-128-CBC + HMAC-SHA256) with the key in the system keychain. The encrypted file is `0600`, owned by a dedicated `tg-syncer` user. Plaintext only exists in memory — never on disk. An attacker would need to escalate to the `tg-syncer` user AND access the keychain, both blocked by systemd hardening.

**Unintended writes** — Telethon's `TelegramClient` has full read/write access to your account. The syncer wraps it in `ReadOnlyTelegramClient` using an **allowlist** — only 15 read methods are permitted, everything else raises `PermissionError`. This is an allowlist, not a blocklist: new Telethon methods in future updates are blocked by default until reviewed.

**Data exfiltration** — Per-UID nftables rules restrict each process to specific IPs at the kernel level. The syncer can only reach Telegram MTProto data centers (`149.154.160.0/20`, `91.108.0.0/16`). The querybot can only reach `api.telegram.org` and `api.anthropic.com`. All other outbound traffic — including to LAN hosts — is dropped. Even with code execution, a compromised process cannot phone home.

**Credential exposure** — The system manages three high-value secrets: a Telethon session key (full Telegram account access), a Bot API token (bot impersonation), and a Claude API key (billing). All credentials are encrypted at rest using `systemd-creds encrypt` (AES-256-GCM with a machine-specific key in `/var/lib/systemd/credential.secret`). At service start, systemd decrypts them into a private RAM-only tmpfs mount — plaintext never touches disk. Each service can only access its own credentials (the querybot cannot read the Telethon session key, and the syncer cannot read the bot token or Claude key). Database authentication uses Unix socket peer auth — no passwords exist. An attacker would need to: (1) gain code execution on the Pi, (2) escalate to root or the specific service user (blocked by `NoNewPrivileges`, dropped capabilities, syscall filtering), and (3) extract the machine key from `/var/lib/systemd/credential.secret` (readable only by root). Full-disk encryption (LUKS) is recommended as an additional layer against physical theft — see [SECURITY_MODEL.md](tg-assistant/docs/SECURITY_MODEL.md) Appendix E.

**Prompt injection** — Malicious messages in synced chats could contain adversarial instructions that Claude sees as context. The architecture constrains the blast radius: the system prompt treats message content as untrusted, only top-K messages go to Claude (not the full DB), and there is no write path — even a manipulated Claude cannot send messages, access files, or modify the database. Worst outcome: a misleading summary shown to the owner.

### Attack Path Analysis

The diagram below shows the three primary attack vectors and how defense-in-depth layers block them. For comprehensive attack trees covering supply chain, physical access, and lateral movement, see [SECURITY_MODEL.md](tg-assistant/docs/SECURITY_MODEL.md#10-attack-trees).

```mermaid
flowchart TD
    Attack["Attacker Goal:<br/>Access user's messages"]

    Attack --> A1["Steal Telethon Session"]
    Attack --> A2["Prompt Injection via Chat"]
    Attack --> A3["Compromise Query Bot"]
    Attack --> A4["Extract Credentials"]

    A1 --> S1{"Encrypted at rest?"}
    S1 -->|"Yes (systemd-creds)"| S2{"Service user access?"}
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

    A4 --> C1{"Plaintext on disk?"}
    C1 -->|"No (encrypted at rest)"| C2{"RAM access?"}
    C2 -->|"Root required"| C3{"Root escalation?"}
    C3 -->|"NoNewPrivileges + syscall filter"| Block4["BLOCKED"]

    style Block1 fill:#c8e6c9
    style Block2 fill:#c8e6c9
    style Block3 fill:#c8e6c9
    style Block4 fill:#c8e6c9
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
│   │   ├── main.py                # Sync loop + dialog processing
│   │   ├── readonly_client.py     # Read-only Telethon wrapper
│   │   ├── message_store.py       # PostgreSQL message storage
│   │   └── embeddings.py          # Local embedding generation
│   ├── querybot/
│   │   ├── main.py                # Bot entry point + wiring
│   │   ├── search.py              # Filtered FTS + vector search + RRF
│   │   ├── llm.py                 # Claude integration (intent + synthesis)
│   │   └── handlers.py            # Bot command/message handlers
│   └── shared/
│       ├── db.py                  # Database connection helpers
│       ├── secrets.py             # Keychain integration
│       ├── audit.py               # Audit logging
│       └── safety.py              # Input validation + injection detection
├── tests/
│   ├── test_querybot.py           # Handler, LLM, and pipeline tests
│   ├── test_readonly_client.py    # Read-only wrapper tests
│   ├── test_search.py             # Search + RRF merge tests
│   ├── test_safety.py             # Sanitizer + validator tests
│   ├── test_shared.py             # DB, secrets, audit tests
│   ├── test_syncer.py             # Sync loop + embedding tests
│   └── prompt-injection-tests.md  # Manual injection test cases
├── docs/
│   ├── QUICKSTART.md              # Deployment checklist
│   ├── SECURITY_MODEL.md          # Full threat model + attack trees
│   └── TELETHON_HARDENING.md      # Telethon-specific security guide
├── scripts/
│   ├── setup.sh                   # Single-command deployment
│   └── monitor-network.sh         # Traffic verification
├── systemd/
│   ├── tg-syncer.service          # Syncer service (hardened)
│   └── tg-querybot.service        # Query bot service (hardened)
├── nftables/
│   └── tg-assistant-firewall.conf # Per-process network rules
└── requirements.txt               # Python dependencies (pinned)
```

### Codebase Size

<!-- UPDATE THIS TABLE WHEN PUSHING CHANGES -->
<!-- Run: find src tests docs config -name '*.py' -o -name '*.md' -o -name '*.toml' | xargs wc -l -->

| Component | Source | Tests | Docs/Config | Notes |
|-----------|--------|-------|-------------|-------|
| **querybot** | 1,137 | 509 | — | Largest: `llm.py` handles intent + formatting + synthesis |
| **syncer** | 796 | 550 | — | `main.py` (sync loop) + `readonly_client.py` (allowlist wrapper) |
| **shared** | 543 | 353 | — | DB, secrets, audit, safety — all cross-cutting concerns |
| **docs** | — | — | 1,745 | `SECURITY_MODEL.md` is 1,173 lines (threat model + attack trees) |
| **config** | — | — | 405 | `settings.toml` + `system_prompt.md` |
| **Total** | **2,509** | **1,588** | **2,150** | **6,247 lines** across 8 files, 6 test files, 5 docs |

Test-to-source ratio: 0.63:1 (134 tests). No external dependencies beyond stdlib for safety/validation layer.

### Database Schema

```sql
-- Messages: synced from all Telegram chats
CREATE TABLE messages (
    message_id         BIGINT NOT NULL,
    chat_id            BIGINT NOT NULL,
    sender_id          BIGINT,
    sender_name        TEXT,
    timestamp          TIMESTAMPTZ NOT NULL,
    text               TEXT,
    raw_json           JSONB,
    embedding          vector(384),
    text_search_vector TSVECTOR
        GENERATED ALWAYS AS (
            to_tsvector('english', COALESCE(text, ''))
        ) STORED,
    text_search_vector_simple TSVECTOR
        GENERATED ALWAYS AS (
            to_tsvector('simple', COALESCE(text, ''))
        ) STORED,
    PRIMARY KEY (message_id, chat_id)
);

-- Role separation: syncer can write, querybot can only read
CREATE ROLE syncer_role;
GRANT INSERT, SELECT ON messages, chats TO syncer_role;

CREATE ROLE querybot_role;
GRANT SELECT ON messages, chats TO querybot_role;
```

### Embedding Backfill (after upgrades)

If you upgrade from an older install or change embedding settings, you may need
to backfill missing embeddings for existing rows. Run:

```bash
TG_ASSISTANT_DB_USER=postgres /opt/tg-assistant/venv/bin/python3 /opt/tg-assistant/scripts/backfill-embeddings.py
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
ls -la /var/lib/tg-syncer/  # Should only have encrypted .session.enc

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
| 2 | Credentials decrypted in RAM at runtime — root can read process memory | **HIGH** |
| 3 | LLM reasoning manipulation via prompt injection | **MEDIUM** |
| 4 | Claude API sees message content (cloud) | **MEDIUM** |
| 5 | Python runtime relies on process isolation, not memory sandbox | **LOW** |
| 6 | Supply chain (Python packages) | **LOW** |

Full threat model with risk matrix and accepted risks: [`tg-assistant/docs/SECURITY_MODEL.md`](tg-assistant/docs/SECURITY_MODEL.md)

---

## License

MIT License. For personal and educational use.

**Telethon**: MIT License — [github.com/LonamiWebs/Telethon](https://github.com/LonamiWebs/Telethon)
**python-telegram-bot**: LGPL-3.0 — [github.com/python-telegram-bot/python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot)
**Claude API**: Subject to [Anthropic's Terms of Service](https://www.anthropic.com/terms)
