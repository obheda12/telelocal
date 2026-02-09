# Future State Plan: Path to Maximum Security

This document outlines the evolutionary path from the current "Option A" deployment to increasingly secure configurations, ultimately achieving near-zero residual risk for all identified threat vectors.

---

## Current State Assessment

### Risk Matrix (Option A - Current)

| Threat | Current Risk | Target Risk | Gap |
|--------|--------------|-------------|-----|
| Credential theft | Very Low | Impossible | Small |
| Unauthorized message sending | Low | Impossible | Medium |
| Data exfiltration to external hosts | Very Low | Impossible | Small |
| Prompt injection → bad reasoning | **Medium** | Low | **Large** |
| Information disclosure via manipulation | **Medium** | Low | **Large** |
| WASM sandbox escape | Very Low | Very Low | None |
| Supply chain compromise | Low | Very Low | Small |
| Configuration drift/error | Low | Very Low | Small |

### Why Current Risks Exist

```mermaid
flowchart TD
    subgraph Problem1["Problem 1: Config-Level Blocking"]
        P1A["Current: sendMessage blocked<br/>by settings.toml"]
        P1B["Risk: Config can be<br/>misconfigured"]
        P1C["Target: sendMessage not in<br/>WASM capabilities"]
        P1D["Result: Architecturally<br/>impossible"]

        P1A -->|"Vulnerable to"| P1B
        P1C -->|"Achieves"| P1D
    end

    subgraph Problem2["Problem 2: Shared Process"]
        P2A["Current: Credentials + LLM<br/>same process"]
        P2B["Risk: Memory corruption<br/>could leak"]
        P2C["Target: Credentials in<br/>separate process"]
        P2D["Result: Full compromise<br/>can't access creds"]

        P2A -->|"Vulnerable to"| P2B
        P2C -->|"Achieves"| P2D
    end

    subgraph Problem3["Problem 3: LLM Susceptibility"]
        P3A["Current: LLM sees<br/>raw messages"]
        P3B["Risk: Prompt injection<br/>affects reasoning"]
        P3C["Target: Multi-model<br/>cross-validation"]
        P3D["Result: Single injection<br/>can't compromise all"]

        P3A -->|"Vulnerable to"| P3B
        P3C -->|"Achieves"| P3D
    end

    style P1B fill:#ffcdd2
    style P2B fill:#ffcdd2
    style P3B fill:#ffcdd2
    style P1D fill:#c8e6c9
    style P2D fill:#c8e6c9
    style P3D fill:#c8e6c9
```

---

## Evolution Phases Overview

```mermaid
flowchart LR
    subgraph P0["Phase 0 (Current)"]
        direction TB
        P0A["Option A:<br/>Config-based blocking"]
        P0R["Risk: Low"]
        P0D["sendMessage blocked<br/>in settings.toml"]
    end

    subgraph P1["Phase 1"]
        direction TB
        P1A["Option B:<br/>Custom WASM Tool"]
        P1R["Risk: Very Low"]
        P1D["No sendMessage<br/>in binary"]
    end

    subgraph P2["Phase 2"]
        direction TB
        P2A["Option B+:<br/>Network Firewall"]
        P2R["Risk: Near Zero"]
        P2D["Kernel-level<br/>traffic filtering"]
    end

    subgraph P3["Phase 3"]
        direction TB
        P3A["Option C:<br/>Air-Gapped"]
        P3R["Cred Theft: Impossible"]
        P3D["Separate processes:<br/>creds vs LLM"]
    end

    subgraph P4["Phase 4"]
        direction TB
        P4A["Option C+:<br/>HSM/TPM"]
        P4R["Hardware Attack Required"]
        P4D["Credentials in<br/>tamper-resistant chip"]
    end

    subgraph P5["Phase 5 (Ultimate)"]
        direction TB
        P5A["Formal<br/>Verification"]
        P5R["Provably Impossible"]
        P5D["Mathematical proof<br/>of security"]
    end

    P0 --> P1 --> P2 --> P3 --> P4 --> P5

    style P0 fill:#ffcdd2
    style P1 fill:#fff3e0
    style P2 fill:#fff9c4
    style P3 fill:#c8e6c9
    style P4 fill:#b2dfdb
    style P5 fill:#b3e5fc
```

### Risk Reduction Summary

```mermaid
xychart-beta
    title "Risk Level by Phase"
    x-axis ["Phase 0", "Phase 1", "Phase 2", "Phase 3", "Phase 4", "Phase 5"]
    y-axis "Risk Score" 0 --> 10
    bar [6, 4, 2, 1, 0.5, 0.1]
```

---

## Phase 1: Custom Read-Only WASM Tool

**Objective**: Move from config-level blocking to architectural impossibility of sending messages.

**Timeline**: 1-2 days

**Risk Reduction**: Message sending moves from "Low" to "Very Low"

### Architecture Comparison

```mermaid
flowchart LR
    subgraph Current["Current (Config Blocking)"]
        direction TB
        C1["Telegram Tool<br/>(full capabilities)"]
        C2["settings.toml<br/>blocked_methods"]
        C3["Runtime Check"]

        C1 --> C2 --> C3
        C3 -->|"Block"| C4["Denied"]
        C3 -->|"Config Error"| C5["ALLOWED!"]
    end

    subgraph Phase1["Phase 1 (Architectural)"]
        direction TB
        P1["Telegram ReadOnly Tool<br/>(limited capabilities)"]
        P2["WASM Runtime"]
        P3["Capability Check"]

        P1 --> P2 --> P3
        P3 -->|"Not in binary"| P4["Cannot Execute"]
    end

    style C5 fill:#ffcdd2
    style P4 fill:#c8e6c9
```

### Implementation

Create a custom WASM tool that only declares read capabilities:

```rust
// telegram_readonly/src/lib.rs
use ironclaw_sdk::prelude::*;

/// Telegram Read-Only Tool
/// This tool CANNOT send messages - the capability is not declared.
/// Even if the LLM requests sendMessage, the WASM runtime will reject it.

#[tool(name = "telegram_readonly")]
pub struct TelegramReadOnly;

#[tool_impl]
impl TelegramReadOnly {
    /// Fetch recent messages from Telegram
    #[tool_method]
    pub async fn get_updates(
        &self,
        ctx: &ToolContext,
        #[arg(desc = "Maximum number of messages to fetch")]
        limit: Option<u32>,
        #[arg(desc = "Offset for pagination")]
        offset: Option<i64>,
    ) -> Result<Vec<TelegramMessage>, ToolError> {
        let limit = limit.unwrap_or(100).min(100);

        let response = ctx.http()
            .get("https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates")
            .query(&[("limit", limit.to_string())])
            .query(&[("offset", offset.map(|o| o.to_string()).unwrap_or_default())])
            .send()
            .await?;

        let updates: TelegramUpdates = response.json().await?;
        Ok(updates.result.into_iter().map(|u| u.message).collect())
    }

    /// Get information about the bot
    #[tool_method]
    pub async fn get_me(&self, ctx: &ToolContext) -> Result<BotInfo, ToolError> {
        let response = ctx.http()
            .get("https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getMe")
            .send()
            .await?;

        Ok(response.json().await?)
    }

    /// Get information about a chat
    #[tool_method]
    pub async fn get_chat(
        &self,
        ctx: &ToolContext,
        #[arg(desc = "Chat ID to get information about")]
        chat_id: i64,
    ) -> Result<ChatInfo, ToolError> {
        let response = ctx.http()
            .get("https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getChat")
            .query(&[("chat_id", chat_id.to_string())])
            .send()
            .await?;

        Ok(response.json().await?)
    }
}

// CRITICAL: Capability declarations
// This is what makes sending ARCHITECTURALLY IMPOSSIBLE
#[capabilities]
impl TelegramReadOnly {
    fn capabilities() -> Vec<Capability> {
        vec![
            // HTTP access ONLY to these specific endpoints
            Capability::Http {
                url_pattern: "https://api.telegram.org/bot*/getUpdates*",
                methods: vec![HttpMethod::Get],
            },
            Capability::Http {
                url_pattern: "https://api.telegram.org/bot*/getMe",
                methods: vec![HttpMethod::Get],
            },
            Capability::Http {
                url_pattern: "https://api.telegram.org/bot*/getChat*",
                methods: vec![HttpMethod::Get],
            },
            // Secret injection
            Capability::Secret("TELEGRAM_BOT_TOKEN"),

            // NOTE: No sendMessage, no POST methods, no other endpoints
            // The WASM runtime will REJECT any attempt to call them
        ]
    }
}
```

### Build and Deploy

```bash
# Build WASM tool
cd telegram_readonly
cargo build --target wasm32-wasi --release

# Install to IronClaw
mkdir -p ~/.ironclaw/tools
cp target/wasm32-wasi/release/telegram_readonly.wasm ~/.ironclaw/tools/

# Update settings.toml
[tools]
telegram = { enabled = false }  # Disable stock tool
telegram_readonly = { enabled = true, path = "~/.ironclaw/tools/telegram_readonly.wasm" }
```

### Verification

```bash
# Attempt to send message via IronClaw
> Send a message to chat 12345 saying "test"

# Expected response:
# "I don't have the capability to send messages. My telegram_readonly tool
#  only supports: get_updates, get_me, get_chat"

# Check WASM capabilities
ironclaw tools inspect telegram_readonly
# Should show ONLY get* methods, no send*
```

---

## Phase 2: Network-Level Firewall

**Objective**: Add kernel-level network restrictions as defense-in-depth against IronClaw bugs.

**Timeline**: 2-4 hours

**Risk Reduction**: Exfiltration moves from "Very Low" to "Near Impossible"

### Defense Layers

```mermaid
flowchart TB
    subgraph App["Application Layer"]
        A1["IronClaw HTTP Allowlist"]
    end

    subgraph Kernel["Kernel Layer (NEW)"]
        K1["nftables / iptables"]
        K2["Network Namespace"]
    end

    subgraph Network["Network Layer"]
        N1["Only Telegram IPs allowed"]
    end

    App --> Kernel --> Network

    Attack["Malicious Request"] --> App
    App -->|"IronClaw Bug"| Kernel
    Kernel -->|"BLOCKED"| Drop["Dropped"]

    style Kernel fill:#c8e6c9
    style Drop fill:#c8e6c9
```

### Implementation - nftables

```bash
# /etc/nftables.conf

#!/usr/sbin/nft -f

flush ruleset

table inet ironclaw_isolation {
    chain output {
        type filter hook output priority 0; policy accept;

        # Allow loopback
        oif "lo" accept

        # Allow established connections
        ct state established,related accept

        # Allow DNS (needed for api.telegram.org resolution)
        udp dport 53 accept
        tcp dport 53 accept

        # Allow ONLY Telegram API IP ranges
        ip daddr 149.154.160.0/20 tcp dport 443 accept
        ip daddr 91.108.4.0/22 tcp dport 443 accept
        ip daddr 91.108.8.0/22 tcp dport 443 accept
        ip daddr 91.108.12.0/22 tcp dport 443 accept
        ip daddr 91.108.16.0/22 tcp dport 443 accept
        ip daddr 91.108.56.0/22 tcp dport 443 accept

        # Block everything else for ironclaw user
        meta skuid "ironclaw" drop
    }
}
```

### Alternative: Per-Process Network Namespace

```bash
# Create isolated network namespace for IronClaw
ip netns add ironclaw_ns

# Create veth pair
ip link add veth-ic type veth peer name veth-ic-ns
ip link set veth-ic-ns netns ironclaw_ns

# Configure routing (only to Telegram)
ip netns exec ironclaw_ns ip route add 149.154.160.0/20 via <gateway>
# ... repeat for other Telegram ranges

# Run IronClaw in namespace
ip netns exec ironclaw_ns sudo -u ironclaw /home/pi/ironclaw/target/release/ironclaw
```

---

## Phase 3: Air-Gapped Architecture (Option C)

**Objective**: Complete separation of credentials from LLM reasoning.

**Timeline**: 1-2 weeks

**Risk Reduction**: Credential theft becomes "Impossible" (not just "Very Low")

### Architecture

```mermaid
flowchart TB
    subgraph CredZone["CREDENTIAL ZONE (Has secrets, NO AI)"]
        Ingest["Ingest Service<br/>(Rust daemon)"]
        Creds["Telegram Credentials"]
        TG["Telegram API"]

        Ingest -->|"Poll"| TG
        Creds -->|"Auth"| Ingest
    end

    subgraph DataZone["DATA ZONE (Shared)"]
        DB[("PostgreSQL<br/>Sanitized messages<br/>Embeddings<br/>Audit logs")]
    end

    subgraph LLMZone["LLM ZONE (Has AI, NO secrets)"]
        Agent["IronClaw Agent"]
        User["User REPL"]

        User -->|"Query"| Agent
    end

    Ingest -->|"Write (sanitized)"| DB
    Agent -->|"Read ONLY"| DB

    style CredZone fill:#ffcdd2
    style LLMZone fill:#c8e6c9
    style DataZone fill:#fff3e0
```

### Component Detail

```mermaid
flowchart LR
    subgraph Ingest["Ingest Service"]
        I1["1. Poll Telegram API"]
        I2["2. Sanitize content"]
        I3["3. Detect injections"]
        I4["4. Write to DB"]

        I1 --> I2 --> I3 --> I4
    end

    subgraph Sanitize["Sanitization Steps"]
        S1["Strip URLs"]
        S2["Detect patterns"]
        S3["Escape chars"]
        S4["Truncate length"]
        S5["Add metadata"]
    end

    I2 --> Sanitize

    subgraph Agent["IronClaw Agent"]
        A1["Read sanitized msgs"]
        A2["NO credentials"]
        A3["NO network access"]
        A4["DB read-only"]
    end

    I4 -->|"Sanitized data"| A1
```

### Ingest Service Implementation

```rust
// ingest-service/src/main.rs

use teloxide::prelude::*;
use sqlx::PgPool;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("TELEGRAM_BOT_TOKEN")?;
    let db_url = std::env::var("DATABASE_URL")?;

    let bot = Bot::new(token);
    let pool = PgPool::connect(&db_url).await?;

    loop {
        match fetch_and_store(&bot, &pool).await {
            Ok(count) => tracing::info!("Processed {} messages", count),
            Err(e) => tracing::error!("Error: {}", e),
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

async fn fetch_and_store(bot: &Bot, pool: &PgPool) -> Result<usize, Error> {
    let updates = bot.get_updates().await?;
    let mut count = 0;

    for update in updates {
        if let Some(msg) = update.message {
            let sanitized = sanitize_message(&msg);

            sqlx::query!(
                r#"
                INSERT INTO messages (telegram_id, chat_id, sender_name, content_sanitized, received_at)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (telegram_id) DO NOTHING
                "#,
                msg.id,
                msg.chat.id,
                msg.from.map(|u| u.first_name),
                sanitized.content,
                msg.date,
            )
            .execute(pool)
            .await?;

            count += 1;
        }
    }

    Ok(count)
}

fn sanitize_message(msg: &Message) -> SanitizedMessage {
    let mut content = msg.text().unwrap_or_default().to_string();

    // Detect injection patterns
    let injection_patterns = [
        "ignore previous", "ignore all instructions", "system prompt",
        "you are now", "new instructions", "override", "admin mode",
    ];

    let mut flags = Vec::new();
    for pattern in &injection_patterns {
        if content.to_lowercase().contains(pattern) {
            flags.push(format!("INJECTION_PATTERN:{}", pattern));
        }
    }

    // Encode/neutralize URLs
    content = URL_REGEX.replace_all(&content, "[URL REMOVED]").to_string();

    // Truncate to prevent context stuffing
    if content.len() > 4000 {
        content = format!("{}... [TRUNCATED]", &content[..4000]);
    }

    SanitizedMessage { content, flags }
}
```

### Database Schema

```sql
-- Strict schema to prevent injection via DB

CREATE TABLE messages (
    id              BIGSERIAL PRIMARY KEY,
    telegram_id     BIGINT UNIQUE NOT NULL,
    chat_id         BIGINT NOT NULL,
    sender_name     VARCHAR(255),
    content_sanitized TEXT NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ DEFAULT NOW(),
    flags           TEXT[],

    CONSTRAINT valid_chat_id CHECK (chat_id > 0),
    CONSTRAINT content_not_empty CHECK (length(content_sanitized) > 0),
    CONSTRAINT content_max_length CHECK (length(content_sanitized) <= 10000)
);

-- IronClaw connects with read-only role
CREATE ROLE ironclaw_readonly;
GRANT CONNECT ON DATABASE ironclaw TO ironclaw_readonly;
GRANT SELECT ON messages TO ironclaw_readonly;
-- NO INSERT, UPDATE, DELETE

-- Ingest service has write access
CREATE ROLE ingest_service;
GRANT CONNECT ON DATABASE ironclaw TO ingest_service;
GRANT INSERT ON messages TO ingest_service;
-- NO SELECT (write-only)
```

---

## Phase 4: Hardware Security Module (HSM/TPM)

**Objective**: Store credentials in tamper-resistant hardware.

**Timeline**: 1 week + hardware procurement

**Risk Reduction**: Credential theft requires physical hardware attack

### Architecture with HSM

```mermaid
flowchart TB
    subgraph Hardware["Hardware Security"]
        HSM["HSM/TPM<br/>Tamper-resistant"]
        Token["Telegram Token<br/>(encrypted in silicon)"]
    end

    subgraph Software["Software Layer"]
        Ingest["Ingest Service"]
        Sign["Request Signing"]
    end

    HSM --> Token
    Token -->|"Never leaves HSM"| Sign
    Sign -->|"Signed request"| Ingest
    Ingest -->|"API call"| TG["Telegram"]

    Attack["Software Compromise"] -.->|"Cannot extract"| HSM

    style HSM fill:#b3e5fc
    style Attack fill:#ffcdd2
```

### Raspberry Pi TPM Option

```bash
# Install TPM2 tools
sudo apt install tpm2-tools tpm2-abrmd

# Store Telegram token in TPM
echo -n "$TELEGRAM_BOT_TOKEN" | tpm2_nvdefine -C o -s 64 -a "ownerread|ownerwrite" 0x1500001
echo -n "$TELEGRAM_BOT_TOKEN" | tpm2_nvwrite -C o -i - 0x1500001

# Token never touches filesystem - read directly from TPM at runtime
```

### External HSM Options

| Device | Price | Security Level |
|--------|-------|----------------|
| YubiHSM 2 | ~$650 | FIPS 140-2 Level 3 |
| Nitrokey HSM 2 | ~$109 | Common Criteria EAL4+ |
| AWS CloudHSM | $/hr | FIPS 140-2 Level 3 |

---

## Phase 5: Formal Verification (Ultimate)

**Objective**: Mathematical proof that the system cannot perform unauthorized actions.

**Timeline**: 3-6 months (research project)

**Risk Reduction**: Unauthorized actions become "Provably Impossible"

### Verification Approach

```mermaid
flowchart TD
    subgraph Properties["Security Properties to Prove"]
        P1["Property 1: No HTTP POST<br/>to telegram.org"]
        P2["Property 2: Token never<br/>in output"]
        P3["Property 3: Only allowlisted<br/>URLs accessed"]
    end

    subgraph Tools["Verification Tools"]
        T1["Kani (Rust)"]
        T2["WASM Symbolic Exec"]
        T3["Network Verifiers"]
    end

    subgraph Targets["Verification Targets"]
        V1["WASM Tool"]
        V2["Host Boundary"]
        V3["Network Rules"]
    end

    P1 --> T1 --> V1
    P2 --> T2 --> V2
    P3 --> T3 --> V3
```

### Example Kani Verification

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_no_send_capability() {
        let tool = TelegramReadOnly;
        let caps = tool.capabilities();

        for cap in caps {
            if let Capability::Http { url_pattern, methods } = cap {
                kani::assert!(
                    !url_pattern.contains("sendMessage"),
                    "Tool must not have sendMessage capability"
                );
                kani::assert!(
                    !methods.contains(&HttpMethod::Post),
                    "Tool must not have POST capability"
                );
            }
        }
    }

    #[kani::proof]
    fn verify_credential_not_leaked() {
        let ctx = kani::any::<ToolContext>();
        let result = TelegramReadOnly.get_updates(&ctx, Some(10), None);

        if let Ok(messages) = result {
            for msg in messages {
                kani::assert!(
                    !msg.content.contains("bot") || !msg.content.contains(":"),
                    "Output must not contain token patterns"
                );
            }
        }
    }
}
```

---

## Summary: Risk Reduction by Phase

```mermaid
flowchart LR
    subgraph Threats["Threat Types"]
        T1["Credential Theft"]
        T2["Send Message"]
        T3["Exfiltration"]
        T4["Bad Reasoning"]
    end

    subgraph P0["Phase 0"]
        T1_0["Very Low"]
        T2_0["Low"]
        T3_0["Very Low"]
        T4_0["Medium"]
    end

    subgraph P3["Phase 3"]
        T1_3["Impossible"]
        T2_3["Impossible"]
        T3_3["Impossible"]
        T4_3["Medium"]
    end

    subgraph P5["Phase 5"]
        T1_5["Proven"]
        T2_5["Proven"]
        T3_5["Proven"]
        T4_5["Low"]
    end

    T1 --> T1_0 --> T1_3 --> T1_5
    T2 --> T2_0 --> T2_3 --> T2_5
    T3 --> T3_0 --> T3_3 --> T3_5
    T4 --> T4_0 --> T4_3 --> T4_5

    style T1_0 fill:#fff3e0
    style T2_0 fill:#ffcdd2
    style T1_3 fill:#c8e6c9
    style T2_3 fill:#c8e6c9
    style T3_3 fill:#c8e6c9
    style T1_5 fill:#b3e5fc
    style T2_5 fill:#b3e5fc
    style T3_5 fill:#b3e5fc
```

### Recommended Implementation Order

| Phase | Effort | Priority | Reason |
|-------|--------|----------|--------|
| **1** | 1-2 days | **HIGH** | Architectural blocking is strictly better |
| **2** | 2-4 hours | **HIGH** | Low effort, high defense-in-depth value |
| 3 | 1-2 weeks | MEDIUM | Only if handling sensitive data |
| 4 | 1 week + $ | LOW | Only for compliance requirements |
| 5 | 3-6 months | RESEARCH | Academic/critical systems only |

---

## Appendix: Residual Risks That Cannot Be Fully Mitigated

Some risks are inherent to the use case:

### 1. LLM Reasoning Manipulation
- **Why it persists**: LLM must process message content to be useful
- **Mitigation**: Multi-model verification, confidence scoring, human review

### 2. Information Already in Context
- **Why it persists**: Agent "knows" messages it has processed
- **Mitigation**: Minimize context window, time-based expiry

### 3. Physical Device Compromise
- **Why it persists**: Physical access enables extraction
- **Mitigation**: Full disk encryption, TPM-sealed keys, physical security

### 4. Upstream Dependencies
- **Why it persists**: We depend on Rust, wasmtime, PostgreSQL, Linux
- **Mitigation**: Keep updated, monitor CVEs, minimal dependencies
