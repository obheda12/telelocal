# Telelocal

Telelocal is a local-first, security-first Telegram query assistant.

It ingests messages from your Telegram account (within configured scope) into a local PostgreSQL database, then answers questions from that local index through a private bot interface.

---

## Table of Contents

- [What This Project Is For](#what-this-project-is-for)
- [Design Priorities](#design-priorities)
- [Architecture At A Glance](#architecture-at-a-glance)
- [Why Not Bot-Per-Chat Workflows](#why-not-bot-per-chat-workflows)
- [Security Design](#security-design)
- [Ingestion And Query Pipeline](#ingestion-and-query-pipeline)
- [Quick Start](#quick-start)
- [Operational UX](#operational-ux)
- [Performance Tuning For Large Accounts](#performance-tuning-for-large-accounts)
- [Repository Layout](#repository-layout)
- [Threat Model And Known Limits](#threat-model-and-known-limits)
- [Incident Response Quick Actions](#incident-response-quick-actions)
- [Documentation Map](#documentation-map)
- [License](#license)

---

## What This Project Is For

Telelocal exists for a specific workflow:

- You have many Telegram chats (especially groups) with different contexts.
- Important asks and decisions get buried quickly.
- You need fast cross-chat retrieval and summaries.
- You want to keep your searchable corpus local, with strict security boundaries.

Typical questions:

> "What needs my attention from the past 24 hours?"
> "What did team X decide about pricing this week?"
> "Show where I was mentioned and whether a response is needed."

Core intent:

- Local-first data ownership
- Security-first isolation and credential handling
- Practical coverage for large chat sets

---

## Design Priorities

### 1. Local Data Plane

- Telegram messages are synced into local Postgres first.
- Query-time filtering/ranking runs locally.
- Only the selected top-K context is sent to Claude for synthesis.

### 2. Security-First Boundaries

- Syncer and querybot run as separate system users.
- Distinct DB roles enforce least privilege.
- Per-process nftables egress policy constrains outbound traffic.
- Secrets are loaded via `systemd` credentials and encrypted at rest.

### 3. Operator Simplicity

- One setup flow: `./scripts/setup.sh`
- One CLI: `telelocal`
- Central scope control: chat types + exclusions + caps

---

## Architecture At A Glance

```mermaid
flowchart LR
    subgraph Telegram["Telegram"]
        TG["Telegram API / MTProto"]
    end

    subgraph Pi["Raspberry Pi / Host"]
        S["tg-syncer<br/>(read-only Telethon wrapper)"]
        DB[("PostgreSQL + pgvector")]
        Q["tg-querybot<br/>(owner-only bot)"]
    end

    subgraph Cloud["Claude API"]
        C["Haiku (intent) + Sonnet (synthesis)"]
    end

    TG --> S
    S --> DB
    Q --> DB
    Q --> C
```

Trust boundary summary:

- Trusted zone: your host + local DB
- Untrusted/less-trusted: Telegram transport, LLM API
- Data minimization: only scoped top-K context leaves host per query

Security layering summary:

```mermaid
flowchart LR
    A["Host hardening<br/>(systemd sandbox + users)"] --> B["Network control<br/>(nftables per service UID)"]
    B --> C["App controls<br/>(read-only wrapper + owner-only handlers)"]
    C --> D["Data controls<br/>(DB roles + scoped retrieval + audit)"]
```

Deeper architecture notes (components, boundaries, compromise containment):

- `tg-assistant/docs/ARCHITECTURE.md`

---

## Why Not Bot-Per-Chat Workflows

Bot API-first tools (including OpenClaw-style patterns) commonly require adding a bot to every chat you want indexed. That is operationally expensive for high-chat-count users and easy to drift (new chats are missed until manually added).

Telelocal chooses account-level read-only ingestion via Telethon, then local indexing.

| Aspect | Bot-Per-Chat Pattern | Telelocal |
|---|---|---|
| Coverage model | Manual bot membership per chat | Central sync scope from account dialogs |
| Operations | Ongoing per-chat administration | One scope policy + optional exclusions |
| Freshness consistency | Depends on bot placement discipline | Freshest-first sync loop across configured scope |
| Security model | Bot token centered | Session + host hardening + role/network isolation |

---

## Security Design

Security in Telelocal is layered, not single-control:

| Layer | Control | Goal |
|---|---|---|
| Application | `ReadOnlyTelegramClient` allowlist (default deny) | Prevent Telegram write actions in syncer |
| Identity | Dedicated users: `tg-syncer`, `tg-querybot` | Reduce lateral movement |
| Database | `syncer_role` write-limited, `querybot_role` read-only on messages | Minimize blast radius |
| Network | nftables per service/UID egress policy | Block arbitrary exfiltration |
| Credentials | `LoadCredentialEncrypted` / `systemd-creds` | No plaintext secrets on disk |
| Auditing | Structured audit log | Forensics + anomaly review |

### Key implementation details

- `ReadOnlyTelegramClient` is an allowlist with default deny (`get_messages`, `iter_messages`, `get_dialogs`, `iter_dialogs`, `get_entity`, `get_participants`, `get_me`, `download_profile_photo`, `connect`, `disconnect`, `is_connected`).
- `tg-querybot` is owner-only at filter registration and handler level.
- Systemd units use hardening controls such as `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, dropped capabilities, and restricted address families.
- Credentials are injected via `LoadCredentialEncrypted=` and decrypted only for service runtime.
- Querybot egress is DNS-refreshed IP-set based (`api.telegram.org`, `api.anthropic.com`), and syncer egress is limited to Telegram MTProto ranges.
- DB role split enforces least privilege (`syncer_role` write-limited for ingestion path; `querybot_role` read-only on message corpus).


### Threat snapshot

| Threat | Severity | Primary mitigation |
|---|---|---|
| Telethon session theft | Critical | Encrypted session at rest + service isolation + key separation |
| Unintended Telegram writes | Critical | Read-only allowlist wrapper (default deny) |
| Data exfiltration from compromised service | High | Per-service nftables egress policy |
| Unauthorized bot use | High | Owner-only filtering + handler checks |
| Prompt injection via synced content | Medium | Untrusted-context prompt design + scoped retrieval + no write path |

---

## Ingestion And Query Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant TG as Telegram
    participant SY as tg-syncer
    participant DB as PostgreSQL
    participant QB as tg-querybot
    participant CL as Claude

    loop sync interval
        SY->>TG: Read dialogs/messages (read-only wrapper)
        TG-->>SY: Messages
        SY->>DB: Insert messages
        Note over SY,DB: embeddings inline or deferred
    end

    QB->>DB: Load chat list + run scoped hybrid search
    QB->>CL: Top-K context only
    CL-->>QB: Answer draft
    QB-->>TG: Reply to owner
```

Ingestion behavior (current design):

- Freshest-first dialog ordering
- Activity window filter via `syncer.max_history_days`
- Pass cap via `syncer.max_active_chats`
- Chat-type scope via `syncer.include_chat_types`
- Optional deferred embeddings (`syncer.defer_embeddings = true`)

Ingestion security properties:

- Messages are pulled via a read-only wrapper path (default deny on unknown Telethon methods).
- Sync runs under dedicated user + service sandbox.
- Sync egress is constrained to Telegram ranges at kernel level.
- Stored corpus is immediately subject to DB role separation.

Query behavior (current design):

- Intent extraction narrows scope (chats, terms, time range)
- Hybrid retrieval (FTS + vector) with lexical gate for short queries
- Fallback path when scoped retrieval is empty

Query security properties:

- Non-owner requests are silently ignored.
- Retrieval is scoped before synthesis to reduce cloud payload.
- Querybot role is read-only for messages.
- Querybot egress is restricted to Telegram Bot API + Anthropic API address sets.

---

## Quick Start

```bash
git clone <your-repo-url> telelocal
cd telelocal/tg-assistant
sudo ./scripts/setup.sh
```

Then:

```bash
telelocal status
telelocal sync-status
telelocal logs
```

Recommended immediately after first deploy:

```bash
sudo ./tests/security-verification.sh
```

For full deployment details and troubleshooting:

- `tg-assistant/docs/QUICKSTART.md`

---

## Operational UX

Day-to-day commands are intentionally small:

| Need | Command |
|---|---|
| Service health | `telelocal status` |
| Ingestion progress | `telelocal sync-status` |
| Runtime logs | `telelocal logs` |
| Adjust scope/exclusions | `sudo telelocal manage-chats` |
| Restart services | `sudo telelocal restart` |
| Deploy checked-out changes safely | `sudo telelocal update <path-to-clone>` |
| Prune old history | `sudo telelocal prune` |

Operator-focused bot prompts:

- `/mentions 1d quick`
- `/summary 1d quick`
- `/summary 1w detailed`
- `/fresh 25 quick`
- `/more`

---

## Performance Tuning For Large Accounts

If your primary goal is faster ingestion and usable freshness:

1. Set `syncer.max_active_chats` (for example, `500`) to cap each pass to freshest chats.
2. Keep `syncer.max_history_days` bounded (for example, `30`) for initial chat sync depth.
3. Narrow `syncer.include_chat_types` (for example, group-focused).
4. Keep `syncer.defer_embeddings = true` to decouple write path from embedding throughput.
5. Tune `querybot.max_intent_chats` to lower intent latency/cost for very large chat lists.

Benchmark helper:

- `./scripts/benchmark-pipeline.sh`

---

## Repository Layout

```text
tg-assistant/
  config/      # settings + system prompt
  docs/        # quickstart, architecture, threat/security model, hardening notes
  nftables/    # egress policy template
  scripts/     # setup, update, ops helpers
  src/
    syncer/    # ingestion pipeline
    querybot/  # query + response pipeline
    shared/    # db/secrets/audit/safety shared utilities
  systemd/     # service and timer units
  tests/       # unit/integration/security checks
```

---

## Threat Model And Known Limits

### High-value assets and actors

Highest-value assets:

- Telethon session + session encryption key (account-level impact if misused)
- bot token and Claude API key
- local message corpus and audit logs

Most relevant threat actors:

- opportunistic internet attacker
- targeted attacker
- malicious chat participant (prompt injection path)
- compromised dependency (in-process code execution)

Key threat snapshot:

| Threat | Severity | Primary controls |
|---|---|---|
| Telethon session theft/use | Critical | encrypted session at rest, credential isolation, host hardening |
| Unintended Telegram writes | Critical | read-only Telethon wrapper allowlist (default deny) |
| Exfiltration from compromised service | High | per-service nftables egress restrictions |
| Unauthorized bot access | High | owner-only filter + handler guard |
| Prompt injection in synced content | Medium | untrusted-context prompt design, scoped retrieval, no direct write path |

Accepted-risk realities:

- root/kernel compromise remains high impact,
- prompt injection risk is reduced but not eliminated,
- scoped/top-K context still leaves host for Claude synthesis.

Operating assumptions:

- host patching is maintained,
- systemd/nftables policy remains intact after updates,
- DNS resolvers used for dynamic API allowlists are trustworthy.

Threat model references:

- concise STRIDE summary: `tg-assistant/docs/THREAT_MODEL.md`
- full model, assumptions, and incident playbook: `tg-assistant/docs/SECURITY_MODEL.md`

---

## Incident Response Quick Actions

If compromise is suspected:

1. Stop services: `sudo systemctl stop tg-syncer tg-querybot`
2. Preserve logs: copy `/var/log/tg-assistant/audit.log` and relevant `journalctl` output
3. Rotate/revoke: Telethon session, API ID/hash, bot token, Claude API key, session encryption key
4. Re-run checks: `sudo ./tests/security-verification.sh`
5. Recreate session and restart only after review

---

## Documentation Map

- Deployment + troubleshooting: `tg-assistant/docs/QUICKSTART.md`
- Architecture reference: `tg-assistant/docs/ARCHITECTURE.md`
- Threat model snapshot: `tg-assistant/docs/THREAT_MODEL.md`
- Telethon hardening details: `tg-assistant/docs/TELETHON_HARDENING.md`
- Full security model and attack trees: `tg-assistant/docs/SECURITY_MODEL.md`

---

## License

MIT License.

Dependencies:

- Telethon: MIT
- python-telegram-bot: LGPL-3.0
- Claude API usage: Anthropic Terms
