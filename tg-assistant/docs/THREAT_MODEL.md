# Threat Model

Concise STRIDE-aligned threat model for Telelocal.

For full control detail and walkthroughs, see `SECURITY_MODEL.md`.

---

## 1. Scope

In scope:

- `tg-syncer`, `tg-querybot`, PostgreSQL role model
- systemd service hardening and credential model
- nftables egress restrictions
- ingest/query data flow boundaries and audit logging

Out of scope:

- Telegram and Anthropic internal controls
- hardware side-channel protections beyond standard host hardening
- supply-chain attestation beyond dependency pinning/review

---

## 2. Assets And Threat Actors

### High-value assets

| Asset | Why it matters |
|---|---|
| Telethon session + session encryption key | equivalent to account-level Telegram access if misused |
| Bot token | bot impersonation/control |
| Claude API key | billable API access and external query path |
| Message corpus (`messages`) | sensitive history and relationship metadata |
| Audit logs (`audit.log`, `audit_log`) | incident reconstruction and anomaly review |

### Main threat actors

| Actor | Capability | Typical objective |
|---|---|---|
| Opportunistic attacker | low-medium | generic RCE, credential theft, abuse |
| Targeted attacker | medium-high | data exfiltration, account takeover |
| Malicious chat participant | low-medium | prompt injection, output manipulation |
| Compromised dependency | high (in-process) | arbitrary code under service identity |
| Physical thief | medium-high | offline disk/credential extraction |

---

## 3. Threat Catalog (STRIDE Snapshot)

| ID | Threat | STRIDE | Severity | Primary controls |
|---|---|---|---|---|
| T1 | Telethon session theft/use | Spoofing / Elevation | Critical | encrypted session, credential isolation, host hardening |
| T2 | Unintended Telegram writes from sync path | Tampering | Critical | read-only Telethon wrapper allowlist |
| T3 | Data exfiltration from compromised service | Information disclosure | High | per-service nftables egress restrictions |
| T4 | Unauthorized bot access | Spoofing | High | owner-only filter + handler guard |
| T5 | Cross-service credential abuse | Elevation | High | per-service credential injection + dedicated users |
| T6 | Query corpus theft via DB role misuse | Information disclosure | High | DB role separation + local DB boundary |
| T7 | Prompt injection and reasoning manipulation | Tampering | Medium | untrusted-context prompting + scoped retrieval + no write path |
| T8 | Supply-chain compromise in Python dependency | Elevation | Medium-High | pinned deps, sandboxing, egress controls |
| T9 | Audit suppression/tampering | Repudiation | Medium | dual sinks and restricted role permissions |
| T10 | Telegram policy/rate-limit disruption | Availability | Medium | conservative sync pacing + retry/backoff |

---

## 4. Representative Attack Paths

### A) Compromised querybot attempts exfiltration

- Attacker gains code execution in `tg-querybot`.
- Process tries outbound traffic to attacker host.
- nftables drops non-allowlisted destination.

Expected outcome:

- arbitrary exfiltration path blocked at kernel layer.

### B) Non-owner probes the bot

- Attacker sends bot messages from non-owner account.
- owner-only checks reject request.

Expected outcome:

- request silently dropped (minimal signal).

### C) Prompt injection payload in synced messages

- Malicious content is ingested and later retrieved.
- LLM can still be influenced despite sanitization and prompt boundaries.

Expected outcome:

- answer-quality risk remains; no direct Telegram write path from model output.

---

## 5. Key Assumptions

1. Host OS and kernel patching are maintained.
2. systemd hardening and nftables rules remain intact after updates.
3. Physical host access is controlled.
4. Owner account and bot-token ownership remain centralized.
5. DNS resolvers used for API allowlist refresh are trustworthy.

---

## 6. Accepted Risk Snapshot

| Risk | Why accepted | Operator expectation |
|---|---|---|
| Root/runtime memory exposure | unavoidable for active runtime | prioritize host hardening and patch cadence |
| Prompt injection residual risk | deterministic elimination is not practical | treat model outputs as advisory |
| Cloud context exposure | required for current answer quality | avoid highly regulated/ultra-sensitive prompts |
| Supply-chain compromise potential | ecosystem reality | controlled dependency update process |
| DNS trust for dynamic allowlists | refresh depends on resolver integrity | use trusted resolvers and monitor refresh logs |

---

## 7. Monitoring Signals

| Signal | Why it matters |
|---|---|
| repeated blocked outbound logs | possible compromise or allowlist drift |
| repeated owner-only blocks | bot probing activity |
| ingest volume collapse without config change | sync/runtime/session failure |
| sudden query volume spike | automation abuse or token compromise |

---

## 8. Incident Response (First Actions)

1. Stop services: `sudo systemctl stop tg-syncer tg-querybot`.
2. Preserve evidence: copy `/var/log/tg-assistant/audit.log` and relevant journal output.
3. Rotate/revoke: Telethon session, API ID/hash, bot token, Claude API key, session encryption key.
4. Re-run verification: `sudo ./tests/security-verification.sh`.

---

## 9. Related Docs

- `SECURITY_MODEL.md` (authoritative model and full walkthroughs)
- `ARCHITECTURE.md` (system architecture and trust boundaries)
- `TELETHON_HARDENING.md` (Telethon-specific controls)
- `QUICKSTART.md` (operator workflow)
