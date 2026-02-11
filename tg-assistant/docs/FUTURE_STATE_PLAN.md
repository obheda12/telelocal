# Future State Plan: Hardening Roadmap

This document outlines the evolutionary path from the current deployment to increasingly secure configurations. Each phase is independent and ordered by effort-to-risk-reduction ratio.

The system under consideration:

- **TG Syncer**: Telethon (MTProto User API) syncing all messages to PostgreSQL
- **Query Bot**: python-telegram-bot (Bot API) + Claude API for natural language queries
- **Database**: PostgreSQL + pgvector on Raspberry Pi
- **Credentials**: Telethon session, bot token, Claude API key, DB passwords

---

## Current State Assessment

### Risk Matrix

| # | Threat | Current Control | Current Risk | Notes |
|---|--------|----------------|--------------|-------|
| T1 | Session theft | Fernet encryption at rest, 0600 perms, dedicated `tg-syncer` user | **Very Low** | Requires privilege escalation + keychain compromise |
| T2 | Unintended writes (Telethon) | Read-only allowlist wrapper (`ReadOnlyTelegramClient`) | **Low** | Wrapper is Python-level; bypassed by runtime exploit |
| T3 | Data exfiltration | nftables per-process IP allowlists at kernel level | **Very Low** | Requires kernel exploit to bypass |
| T4 | Prompt injection / bad LLM reasoning | System prompt hardening, data minimization (top-K only) | **Medium** | Inherent to LLM-in-the-loop design |
| T5 | Information disclosure | Owner-only check (hardcoded user ID), rate limiting | **Medium** | Crafted queries can extract sensitive context |
| T6 | Account ban (Telegram ToS) | Conservative rate limits, human-like access patterns | **Medium** | Telegram policy is opaque; risk cannot be eliminated |
| T7 | Supply chain compromise | Pinned versions, audited dependencies | **Low** | Python ecosystem has large attack surface |

### Why Medium Risks Persist

| Problem | Current State | Why It Stays Medium |
|---------|---------------|---------------------|
| **Prompt injection** | Synced messages flow into Claude context | LLM must see message content to be useful; any message could contain adversarial text |
| **Information disclosure** | Bot has SELECT access to all synced messages | Owner's queries could be manipulated to reveal data from sensitive chats |
| **Account ban** | Telethon MTProto access has stricter rate limits | Telegram does not publish exact thresholds; automated access always carries ban risk |

---

## Evolution Phases Overview

| Phase | Change | Effort | Primary Risk Reduction |
|-------|--------|--------|------------------------|
| **Current** | Read-only wrapper + nftables + systemd | Done | Baseline deployment |
| **1** | Local embeddings (all-MiniLM-L6-v2) | 1 day | Eliminate cloud data exposure during sync |
| **2** | Network namespace isolation | 2-4 hours | Kernel-level per-process network isolation |
| **3** | Encrypted database (pgcrypto) | 1 day | Data at rest protection against physical theft |
| **4** | HSM/TPM for session key | 1 week + hardware | Hardware-backed credential protection |
| **5** | Air-gapped sync (USB/sneakernet) | 2 weeks | Eliminate ALL network attack surface on query machine |

---

## Phase 1: Local Embeddings

**Objective**: Remove the cloud embedding API from the sync path, eliminating the transmission of raw message content to any third party during message ingestion.

**Timeline**: 1 day

**Risk Reduction**: T3 (data exfiltration) improves from Very Low to Near Zero during sync; eliminates an entire outbound data flow.

### Current vs Phase 1

| Aspect | Current (Voyage-3 API) | Phase 1 (all-MiniLM-L6-v2) |
|--------|------------------------|----------------------------|
| Embedding dimensions | 1024 | 384 |
| Embedding quality | High | Moderate |
| Latency on Pi 4 | ~100ms (network) | ~50ms (local CPU) |
| Cloud data exposure during sync | Message content sent to embedding API | **None** |
| Cost | Per-token | Free |
| Dependencies | Network + API key | `sentence-transformers` (local) |

### Trade-off Analysis

The quality trade-off is real: 384-dimensional all-MiniLM-L6-v2 embeddings will produce slightly less precise semantic search results than 1024-dimensional Voyage-3 embeddings. However:

1. The query path ALREADY sends top-K message content to Claude API for reasoning, so cloud exposure during queries is unchanged.
2. The sync path is high-volume (thousands of messages per day across all chats). Eliminating cloud exposure here has disproportionate security value.
3. Full-text search (PostgreSQL `tsvector`) serves as a fallback for cases where embedding quality is insufficient.

### Implementation

```python
# src/syncer/embeddings.py

from sentence_transformers import SentenceTransformer

class LocalEmbedder:
    """Generate embeddings locally using all-MiniLM-L6-v2.

    No message content leaves the device during embedding generation.
    """

    def __init__(self):
        # Model downloaded once, cached locally (~80MB)
        self.model = SentenceTransformer('all-MiniLM-L6-v2')

    def embed(self, text: str) -> list[float]:
        """Generate 384-dimensional embedding for a single text."""
        return self.model.encode(text).tolist()

    def embed_batch(self, texts: list[str], batch_size: int = 32) -> list[list[float]]:
        """Batch embedding for sync efficiency."""
        return self.model.encode(texts, batch_size=batch_size).tolist()
```

### Database Migration

```sql
-- Migrate embedding column from 1024 to 384 dimensions
ALTER TABLE messages ADD COLUMN embedding_local vector(384);

-- Backfill (run once via script)
-- Then swap columns:
ALTER TABLE messages DROP COLUMN embedding;
ALTER TABLE messages RENAME COLUMN embedding_local TO embedding;

-- Recreate index
CREATE INDEX idx_messages_embedding ON messages
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
```

### Verification

```bash
# Verify no outbound connections during sync
sudo nft monitor trace | grep -v "149.154\|91.108"  # Should show NO non-Telegram traffic

# Verify embedding quality (compare search results before/after)
python -c "
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('all-MiniLM-L6-v2')
emb = model.encode('test message')
print(f'Dimensions: {len(emb)}')  # Should print 384
print(f'Model loaded successfully from local cache')
"
```

### nftables Update

After Phase 1, the syncer's nftables rules can be tightened to remove the embedding API endpoint entirely:

```bash
# BEFORE Phase 1: syncer needs Telegram MTProto + embedding API
# AFTER Phase 1:  syncer needs Telegram MTProto ONLY

# Remove embedding API from syncer's allowlist
# The syncer process should now have ZERO HTTPS outbound connections
```

---

## Phase 2: Network Namespace Isolation

**Objective**: Isolate each service in its own Linux network namespace, providing kernel-level network segmentation that persists even if nftables rules are misconfigured.

**Timeline**: 2-4 hours

**Risk Reduction**: T3 (data exfiltration) gains a second independent kernel-level barrier. nftables misconfiguration no longer results in unrestricted network access.

### Why Namespaces on Top of nftables

nftables is a single point of failure for network policy:

| Failure Mode | nftables Only | nftables + Namespace |
|-------------|---------------|----------------------|
| Rule misconfiguration (typo) | **Full network access** | Namespace still restricts |
| `nft flush ruleset` (accidental) | **Full network access** | Namespace still restricts |
| nftables service not started | **Full network access** | Namespace still restricts |
| Kernel nftables bug | **Full network access** | Namespace still restricts |
| Namespace misconfiguration | N/A (no namespace) | nftables still restricts |

Two independent kernel-level mechanisms. Both must fail for unrestricted access.

### Architecture

```
Host Network Namespace
  |
  +-- veth-syncer <-> veth-syncer-ns (syncer namespace)
  |     Routes: Telegram MTProto IPs only
  |     No default route (no internet fallback)
  |
  +-- veth-querybot <-> veth-querybot-ns (querybot namespace)
  |     Routes: api.telegram.org + api.anthropic.com only
  |     No default route
  |
  +-- PostgreSQL (localhost only, host namespace)
        Accessible via veth from both namespaces
```

### Implementation

```bash
#!/bin/bash
# scripts/setup-netns.sh — Create network namespaces for each service

set -euo pipefail

# --- Syncer namespace ---
ip netns add ns-syncer

# Create veth pair
ip link add veth-syncer type veth peer name veth-syncer-ns
ip link set veth-syncer-ns netns ns-syncer

# Assign IPs (private subnet)
ip addr add 10.0.1.1/30 dev veth-syncer
ip netns exec ns-syncer ip addr add 10.0.1.2/30 dev veth-syncer-ns

# Bring up interfaces
ip link set veth-syncer up
ip netns exec ns-syncer ip link set veth-syncer-ns up
ip netns exec ns-syncer ip link set lo up

# Routes: ONLY Telegram MTProto IP ranges
ip netns exec ns-syncer ip route add 149.154.160.0/20 via 10.0.1.1
ip netns exec ns-syncer ip route add 91.108.4.0/22   via 10.0.1.1
ip netns exec ns-syncer ip route add 91.108.8.0/22   via 10.0.1.1
ip netns exec ns-syncer ip route add 91.108.12.0/22  via 10.0.1.1
ip netns exec ns-syncer ip route add 91.108.16.0/22  via 10.0.1.1
ip netns exec ns-syncer ip route add 91.108.56.0/22  via 10.0.1.1
# NO default route — anything not explicitly routed is unreachable

# --- Query Bot namespace ---
ip netns add ns-querybot

ip link add veth-querybot type veth peer name veth-querybot-ns
ip link set veth-querybot-ns netns ns-querybot

ip addr add 10.0.2.1/30 dev veth-querybot
ip netns exec ns-querybot ip addr add 10.0.2.2/30 dev veth-querybot-ns

ip link set veth-querybot up
ip netns exec ns-querybot ip link set veth-querybot-ns up
ip netns exec ns-querybot ip link set lo up

# Routes: Telegram Bot API + Anthropic API
# Resolve current IPs and add routes
for ip in $(dig +short api.telegram.org); do
    ip netns exec ns-querybot ip route add "$ip/32" via 10.0.2.1
done
for ip in $(dig +short api.anthropic.com); do
    ip netns exec ns-querybot ip route add "$ip/32" via 10.0.2.1
done
# NO default route

# --- DNS ---
# Provide DNS resolution via host (forward only to Telegram/Anthropic IPs)
# Each namespace gets a resolv.conf pointing to host veth IP
mkdir -p /etc/netns/ns-syncer /etc/netns/ns-querybot
echo "nameserver 10.0.1.1" > /etc/netns/ns-syncer/resolv.conf
echo "nameserver 10.0.2.1" > /etc/netns/ns-querybot/resolv.conf

# --- NAT on host for forwarding ---
iptables -t nat -A POSTROUTING -s 10.0.1.0/30 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.0.2.0/30 -j MASQUERADE
iptables -A FORWARD -i veth-syncer -j ACCEPT
iptables -A FORWARD -i veth-querybot -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "Network namespaces created. Run services with:"
echo "  ip netns exec ns-syncer sudo -u tg-syncer python -m syncer"
echo "  ip netns exec ns-querybot sudo -u tg-querybot python -m querybot"
```

### Systemd Integration

```ini
# systemd/tg-syncer.service (updated)
[Service]
# Run inside network namespace
ExecStart=/usr/sbin/ip netns exec ns-syncer \
    /usr/bin/sudo -u tg-syncer \
    /home/tg-syncer/venv/bin/python -m syncer

# Existing hardening (unchanged)
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

### Verification

```bash
# From syncer namespace, verify ONLY Telegram is reachable
ip netns exec ns-syncer ping -c 1 149.154.167.50    # Should succeed (Telegram DC)
ip netns exec ns-syncer ping -c 1 8.8.8.8           # Should FAIL (no route)
ip netns exec ns-syncer curl https://example.com     # Should FAIL (no route)

# From querybot namespace, verify limited connectivity
ip netns exec ns-querybot curl -I https://api.telegram.org  # Should succeed
ip netns exec ns-querybot curl -I https://api.anthropic.com # Should succeed
ip netns exec ns-querybot curl -I https://example.com       # Should FAIL
```

---

## Phase 3: Encrypted Database

**Objective**: Encrypt message content at rest in PostgreSQL using pgcrypto column-level encryption. Protection against disk theft, backup theft, and unauthorized direct database access.

**Timeline**: 1 day

**Risk Reduction**: New protection against physical threats (disk theft, backup exfiltration). Messages unreadable without the decryption key, even with full database access.

### Threat Model for Encrypted DB

| Attack | Without pgcrypto | With pgcrypto |
|--------|-----------------|---------------|
| Disk/SD card theft | All messages readable in plaintext | Messages encrypted; key required |
| DB backup copied | All messages readable | Messages encrypted; key required |
| Unauthorized `psql` access | `SELECT * FROM messages` reveals all | Content column returns ciphertext |
| DB role privilege escalation | Full content access | Still need decryption key (stored separately) |
| Full software compromise | Plaintext in memory during query | Plaintext in memory during query (unchanged) |

Note: pgcrypto does NOT protect against an attacker who has compromised the running application process, because the decryption key must be available in memory during queries. It protects against offline/at-rest attacks.

### Key Management

The decryption key is stored SEPARATELY from database credentials:

```
Database credentials:  systemd EnvironmentFile (/etc/tg-assistant/db.env)
Decryption key:        System keychain (libsecret / gnome-keyring)

Both are needed to read message content.
DB credentials alone -> ciphertext only.
Keychain alone -> no database access.
```

### Implementation

```sql
-- Enable pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Add encrypted content column
ALTER TABLE messages ADD COLUMN content_encrypted BYTEA;

-- Encrypt existing messages (one-time migration)
-- Run from application with decryption key available
UPDATE messages
SET content_encrypted = pgp_sym_encrypt(content, 'DECRYPTION_KEY_HERE')
WHERE content_encrypted IS NULL;

-- After verifying migration, drop plaintext column
ALTER TABLE messages DROP COLUMN content;

-- Create wrapper functions for application use
CREATE OR REPLACE FUNCTION insert_message(
    p_telegram_msg_id BIGINT,
    p_chat_id BIGINT,
    p_chat_title VARCHAR(255),
    p_sender_id BIGINT,
    p_sender_name VARCHAR(255),
    p_content TEXT,
    p_timestamp TIMESTAMPTZ,
    p_embedding vector(384),
    p_key TEXT
) RETURNS void AS $$
BEGIN
    INSERT INTO messages (
        telegram_msg_id, chat_id, chat_title, sender_id, sender_name,
        content_encrypted, timestamp, embedding
    ) VALUES (
        p_telegram_msg_id, p_chat_id, p_chat_title, p_sender_id, p_sender_name,
        pgp_sym_encrypt(p_content, p_key), p_timestamp, p_embedding
    ) ON CONFLICT (telegram_msg_id, chat_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION search_messages(
    p_query TEXT,
    p_key TEXT,
    p_limit INT DEFAULT 20
) RETURNS TABLE (
    id BIGINT,
    chat_title VARCHAR(255),
    sender_name VARCHAR(255),
    content TEXT,
    timestamp TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        m.id,
        m.chat_title,
        m.sender_name,
        pgp_sym_decrypt(m.content_encrypted, p_key)::TEXT as content,
        m.timestamp
    FROM messages m
    ORDER BY m.timestamp DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;
```

### Application Changes

```python
# src/shared/db.py (updated for encrypted content)

import keyring

class EncryptedMessageStore:
    def __init__(self, db_pool):
        self.pool = db_pool
        # Decryption key from system keychain — NOT from env or config file
        self._key = keyring.get_password("tg-assistant", "pgcrypto-key")
        if not self._key:
            raise RuntimeError("Decryption key not found in system keychain")

    async def insert_message(self, msg: dict):
        await self.pool.execute(
            "SELECT insert_message($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            msg['telegram_msg_id'], msg['chat_id'], msg['chat_title'],
            msg['sender_id'], msg['sender_name'], msg['content'],
            msg['timestamp'], msg['embedding'], self._key
        )

    async def search(self, query_embedding: list[float], limit: int = 20):
        rows = await self.pool.fetch("""
            SELECT id, chat_title, sender_name,
                   pgp_sym_decrypt(content_encrypted, $1) as content,
                   timestamp
            FROM messages
            ORDER BY embedding <=> $2::vector
            LIMIT $3
        """, self._key, query_embedding, limit)
        return rows
```

### Full-Text Search Limitation

With pgcrypto column-level encryption, PostgreSQL full-text search (`tsvector`) cannot index encrypted content. Search strategies after Phase 3:

| Search Method | Works with Encryption? | Notes |
|---------------|----------------------|-------|
| Vector similarity (pgvector) | Yes | Embeddings are not encrypted (they are lossy projections, not reversible to content) |
| Full-text search (tsvector) | **No** | Cannot index encrypted columns |
| Decrypt-then-search | Yes, but slow | Decrypts all rows, then filters in application |
| Encrypted search index | Possible (advanced) | Maintain a separate encrypted FTS index; significant complexity |

Recommended approach: rely on vector search as the primary retrieval method and accept the FTS limitation.

### Verification

```bash
# Verify content is encrypted at rest
sudo -u postgres psql -d tg_assistant -c \
    "SELECT id, content_encrypted FROM messages LIMIT 1;"
# Should show binary data, not readable text

# Verify decryption works with correct key
sudo -u postgres psql -d tg_assistant -c \
    "SELECT pgp_sym_decrypt(content_encrypted, 'WRONG_KEY') FROM messages LIMIT 1;"
# Should ERROR: Wrong key or corrupt data

# Verify backup contains only ciphertext
pg_dump tg_assistant | grep -c "readable message content"
# Should return 0
```

---

## Phase 4: HSM/TPM for Session Key

**Objective**: Store the Telethon session encryption key in tamper-resistant hardware (TPM or external HSM). Even full software compromise cannot extract the session key.

**Timeline**: 1 week + hardware procurement

**Risk Reduction**: T1 (session theft) moves from Very Low to Near Impossible. Requires physical hardware attack.

### Why HSM/TPM Matters

The Telethon session file grants full account access. Currently, it is encrypted with a key stored in the system keychain. The keychain is software-based: a process with sufficient privileges can extract the key from memory.

With HSM/TPM, the key never exists in extractable form in software:

| Attack | Software Keychain | HSM/TPM |
|--------|-------------------|---------|
| Privilege escalation to root | Key extractable from keychain memory | Key never leaves HSM hardware |
| Memory dump of syncer process | Key in process memory | Only HSM handle in memory |
| Full disk image | Key in keychain storage files | Key in tamper-resistant hardware |
| Physical device theft | Key on disk (encrypted by login) | Key in separate hardware (removable HSM) |

### Raspberry Pi TPM Options

**Option A: TPM HAT (Hardware Attached on Top)**

The Raspberry Pi does not have a built-in TPM. A TPM HAT connects via SPI:

| Product | Interface | TPM Version | Approximate Cost |
|---------|-----------|-------------|-----------------|
| Infineon OPTIGA SLB 9670 (Pi HAT) | SPI | TPM 2.0 | ~$20-30 |
| LetsTrust TPM for Raspberry Pi | SPI | TPM 2.0 | ~$25 |

```bash
# Enable SPI and TPM on Raspberry Pi
echo "dtoverlay=tpm-slb9670" >> /boot/config.txt
reboot

# Install TPM2 tools
sudo apt install tpm2-tools tpm2-abrmd

# Verify TPM is detected
tpm2_getcap properties-fixed
# Should show manufacturer info

# Store session encryption key in TPM
# Define NV index for the key (64 bytes)
tpm2_nvdefine -C o -s 64 \
    -a "ownerread|ownerwrite|authread|authwrite" \
    0x1500001

# Write key to TPM (key is generated once, never stored on disk)
python3 -c "import secrets; print(secrets.token_hex(32))" | \
    tpm2_nvwrite -C o -i - 0x1500001

# Read key at runtime (for session decryption)
tpm2_nvread -C o -s 64 0x1500001
```

**Option B: External USB HSM**

| Device | Price | Certification | Interface |
|--------|-------|---------------|-----------|
| YubiHSM 2 | ~$650 | FIPS 140-2 Level 3 | USB |
| Nitrokey HSM 2 | ~$109 | Common Criteria EAL4+ | USB |
| SoloKeys Solo V2 | ~$40 | None (open source) | USB |

The YubiHSM 2 and Nitrokey HSM 2 are tamper-evident: physical attempts to extract keys destroy the device.

### Application Integration (TPM)

```python
# src/shared/secrets.py (updated for TPM)

import subprocess

class TPMKeyStore:
    """Read encryption keys from TPM 2.0 hardware.

    The key never exists on disk. It is read from the TPM
    at process startup and held in memory only while the
    process is running.
    """

    NV_INDEX = "0x1500001"

    def get_session_key(self) -> bytes:
        """Read the Telethon session encryption key from TPM."""
        result = subprocess.run(
            ["tpm2_nvread", "-C", "o", "-s", "64", self.NV_INDEX],
            capture_output=True, check=True
        )
        return result.stdout.strip()

    def get_pgcrypto_key(self) -> str:
        """Read the pgcrypto decryption key from TPM (Phase 3+4 combined)."""
        result = subprocess.run(
            ["tpm2_nvread", "-C", "o", "-s", "64", "0x1500002"],
            capture_output=True, check=True
        )
        return result.stdout.strip().decode('utf-8')
```

### Application Integration (YubiHSM 2)

```python
# src/shared/secrets.py (YubiHSM variant)

import yubihsm
from yubihsm.objects import WrapKey

class YubiHSMKeyStore:
    """Read encryption keys from YubiHSM 2.

    Keys are generated inside the HSM and never exported.
    Decryption operations happen inside the HSM hardware.
    """

    def __init__(self):
        self.hsm = yubihsm.YubiHsm.connect("http://localhost:12345")
        self.session = self.hsm.create_session_derived(1, "password")

    def decrypt_session_file(self, encrypted_session: bytes) -> bytes:
        """Decrypt Telethon session file using HSM-held key.

        The decryption happens INSIDE the HSM hardware.
        The raw key never enters application memory.
        """
        wrap_key = self.session.get_object(2, WrapKey)
        return wrap_key.unwrap_data(encrypted_session)
```

### Verification

```bash
# Verify TPM holds the key
tpm2_nvreadpublic 0x1500001
# Should show NV index metadata

# Verify key is NOT on the filesystem
grep -r "session_key\|encryption_key" /home/tg-syncer/ /etc/tg-assistant/
# Should find nothing

# Verify syncer can start and decrypt session via TPM
sudo -u tg-syncer python -c "
from shared.secrets import TPMKeyStore
ks = TPMKeyStore()
key = ks.get_session_key()
print(f'Key loaded from TPM: {len(key)} bytes')
"
```

---

## Phase 5: Air-Gapped Sync

**Objective**: Physically separate the sync machine (which holds Telethon credentials and connects to Telegram) from the query machine (which runs the bot and Claude API). Messages transfer via USB storage or serial cable.

**Timeline**: 2 weeks

**Risk Reduction**: The query machine has ZERO network attack surface. Complete physical isolation between credential zone and LLM zone.

**This phase is extreme and only justified for highly sensitive use cases.**

### Architecture

```
+---------------------------+          USB Drive          +---------------------------+
|      SYNC MACHINE         |     (sneakernet transfer)   |      QUERY MACHINE        |
|      (Raspberry Pi #1)    | =========================>  |      (Raspberry Pi #2)     |
|                           |                             |                           |
|  Telethon (MTProto)       |    Encrypted message        |  Query Bot (Bot API)      |
|  Session credentials      |    export files             |  Claude API               |
|  Read-only wrapper        |    (AES-256-GCM)            |  PostgreSQL + pgvector    |
|  nftables: TG only        |                             |  nftables: TG Bot +       |
|                           |                             |            Anthropic only  |
|  NO Claude API            |                             |                           |
|  NO Bot API               |                             |  NO Telethon session      |
|  NO query interface       |                             |  NO MTProto access        |
|                           |                             |  NO direct TG message     |
|  Exports: encrypted       |                             |      access               |
|  message batches to USB   |                             |                           |
+---------------------------+                             +---------------------------+
```

### Security Properties

| Property | Single Machine (Current) | Air-Gapped (Phase 5) |
|----------|-------------------------|----------------------|
| Session + LLM in same device | Yes | **No** (different hardware) |
| Network path from LLM to Telegram | Exists (via host network) | **Does not exist** |
| Compromise of query machine exposes session | Yes (keychain on same device) | **No** (session on sync machine) |
| Remote exploit chain to session | Anthropic API -> query process -> privilege escalation -> keychain | **Impossible** (no network path) |
| Real-time message access | Yes | No (batch delay) |

### Implementation: Sync Machine Export

```python
# sync_machine/export_messages.py

import json
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

class MessageExporter:
    """Export synced messages to encrypted files for USB transfer."""

    def __init__(self, db_pool, export_key: bytes):
        self.pool = db_pool
        self.fernet = Fernet(export_key)
        self.export_dir = "/mnt/usb/tg-export"

    async def export_since(self, since: datetime) -> str:
        """Export all messages since the given timestamp."""
        rows = await self.pool.fetch("""
            SELECT telegram_msg_id, chat_id, chat_title, sender_id,
                   sender_name, content, message_type, reply_to_msg_id,
                   timestamp
            FROM messages
            WHERE synced_at > $1
            ORDER BY timestamp ASC
        """, since)

        messages = [dict(row) for row in rows]

        # Serialize and encrypt
        plaintext = json.dumps(messages, default=str).encode('utf-8')
        ciphertext = self.fernet.encrypt(plaintext)

        # Write to USB mount point
        filename = f"export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.enc"
        filepath = os.path.join(self.export_dir, filename)

        with open(filepath, 'wb') as f:
            f.write(ciphertext)

        # Write manifest (unencrypted metadata)
        manifest = {
            "filename": filename,
            "message_count": len(messages),
            "time_range": {
                "from": str(since),
                "to": str(datetime.utcnow()),
            },
            "sha256": hashlib.sha256(ciphertext).hexdigest(),
        }

        manifest_path = os.path.join(self.export_dir, f"{filename}.manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        return filepath
```

### Implementation: Query Machine Import

```python
# query_machine/import_messages.py

import json
import hashlib
from cryptography.fernet import Fernet

class MessageImporter:
    """Import encrypted message files from USB into query database."""

    def __init__(self, db_pool, import_key: bytes, embedder):
        self.pool = db_pool
        self.fernet = Fernet(import_key)
        self.embedder = embedder  # Local embedder (Phase 1)

    async def import_file(self, filepath: str) -> int:
        """Import an encrypted export file into the query database."""

        # Verify integrity via manifest
        manifest_path = f"{filepath}.manifest.json"
        with open(manifest_path) as f:
            manifest = json.load(f)

        with open(filepath, 'rb') as f:
            ciphertext = f.read()

        actual_hash = hashlib.sha256(ciphertext).hexdigest()
        if actual_hash != manifest['sha256']:
            raise ValueError(
                f"Integrity check failed: expected {manifest['sha256']}, "
                f"got {actual_hash}"
            )

        # Decrypt and parse
        plaintext = self.fernet.decrypt(ciphertext)
        messages = json.loads(plaintext)

        # Generate local embeddings and insert
        texts = [m['content'] for m in messages]
        embeddings = self.embedder.embed_batch(texts)

        count = 0
        for msg, embedding in zip(messages, embeddings):
            await self.pool.execute("""
                INSERT INTO messages (
                    telegram_msg_id, chat_id, chat_title, sender_id,
                    sender_name, content, message_type, reply_to_msg_id,
                    timestamp, embedding
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                ON CONFLICT (telegram_msg_id, chat_id) DO NOTHING
            """, msg['telegram_msg_id'], msg['chat_id'], msg['chat_title'],
                msg['sender_id'], msg['sender_name'], msg['content'],
                msg['message_type'], msg['reply_to_msg_id'],
                msg['timestamp'], embedding)
            count += 1

        return count
```

### Operational Workflow

1. Sync machine runs continuously, pulling messages via Telethon.
2. Periodically (e.g., every hour), sync machine exports new messages to encrypted file on USB drive.
3. Operator physically moves USB drive to query machine.
4. Query machine imports encrypted file, generates local embeddings, inserts into PostgreSQL.
5. User queries via bot as normal.

Latency cost: queries will be delayed by the USB transfer interval. For most personal assistant use cases, hourly batches are acceptable.

### Verification

```bash
# On sync machine: verify NO bot API or Claude API connectivity
curl -I https://api.telegram.org/bot    # Should FAIL (not in nftables)
curl -I https://api.anthropic.com       # Should FAIL

# On query machine: verify NO MTProto connectivity
python3 -c "
from telethon import TelegramClient
# Should fail to connect — MTProto IPs not routable
"

# Verify export/import integrity
sha256sum /mnt/usb/tg-export/export_*.enc
# Compare with manifest
```

---

## Risk Reduction Summary

### Threat vs Phase Matrix

How each phase reduces each threat's residual risk:

| Threat | Current | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 |
|--------|---------|---------|---------|---------|---------|---------|
| T1: Session theft | Very Low | Very Low | Very Low | Very Low | **Near Zero** | **Near Zero** (on separate hardware) |
| T2: Unintended writes | Low | Low | Low | Low | Low | **Very Low** (no LLM on sync machine) |
| T3: Data exfiltration | Very Low | **Lower** (no embedding API) | **Near Zero** (dual kernel barriers) | Near Zero | Near Zero | **Impossible** (no network on query machine for session data) |
| T4: Prompt injection | Medium | Medium | Medium | Medium | Medium | Medium |
| T5: Info disclosure | Medium | Medium | Medium | Medium | Medium | **Lower** (batch delay limits real-time extraction) |
| T6: Account ban | Medium | Medium | Medium | Medium | Medium | Medium |
| T7: Supply chain | Low | Low | Low | Low | Low | **Very Low** (attack surface split across two machines) |

### Comparison: Current vs Phase 3 vs Phase 5

| Dimension | Current | After Phase 3 | After Phase 5 |
|-----------|---------|---------------|---------------|
| **Session protection** | Encrypted file + keychain | Encrypted file + keychain | Session on separate hardware; query machine has no session |
| **Data at rest** | Plaintext in PostgreSQL | **Encrypted** (pgcrypto AES) | Encrypted + on separate machine |
| **Cloud exposure (sync)** | Message content to embedding API | Message content to embedding API | **None** (sync machine has no cloud API) |
| **Cloud exposure (query)** | Top-K messages to Claude API | Top-K messages to Claude API | Top-K messages to Claude API (unchanged) |
| **Network attack surface** | nftables per-process rules | nftables per-process rules | **Zero** on query machine for credential theft |
| **Physical theft impact** | All data + credentials on one device | Encrypted data + credentials on one device | Credentials on sync machine only; query machine has no session |
| **Operational complexity** | Low (single device) | Low (single device) | **High** (two devices, USB transfer workflow) |
| **Query latency** | Real-time | Real-time | **Batch-delayed** (USB transfer interval) |
| **Hardware cost** | ~$80 (one Pi) | ~$80 (one Pi) | **~$160** (two Pis) + USB drives |

---

## Recommended Implementation Order

| Priority | Phase | Effort | Justification |
|----------|-------|--------|---------------|
| **1st** | Phase 1: Local Embeddings | 1 day | Highest ratio of risk reduction to effort. Eliminates an entire outbound data flow (message content to embedding API) with minimal code change. Also reduces cost and latency. |
| **2nd** | Phase 2: Network Namespaces | 2-4 hours | Very low effort for meaningful defense-in-depth. Provides a second independent kernel-level network barrier. Protects against nftables misconfiguration, which is the most likely operational error. |
| **3rd** | Phase 3: Encrypted Database | 1 day | Protects against physical threats (disk theft, backup exfiltration). Important if the Raspberry Pi is in a location where physical access by others is possible (shared housing, office). |
| **4th** | Phase 4: HSM/TPM | 1 week + hardware | Only justified if you assess session theft as a significant threat after Phases 1-3. Requires hardware purchase. Consider after Phases 1-3 are stable. |
| **5th** | Phase 5: Air-Gapped Sync | 2 weeks | Extreme measure. Only justified for users handling highly sensitive data (journalists, activists, legal professionals). The operational burden (USB transfers) is significant. |

### Decision Framework

```
Do you send messages content to a cloud embedding API during sync?
  YES -> Implement Phase 1 first
  NO  -> (already using local embeddings)

Could nftables misconfiguration expose your services?
  YES -> Implement Phase 2
  NO  -> (unlikely, but low effort regardless)

Is physical theft of the Pi a realistic threat?
  YES -> Implement Phase 3
  NO  -> Skip or defer Phase 3

Is software-level credential theft a realistic threat?
  YES -> Implement Phase 4 (HSM/TPM)
  NO  -> Skip Phase 4

Are you handling data where a full remote compromise is unacceptable?
  YES -> Implement Phase 5 (air gap)
  NO  -> Phases 1-3 are sufficient for personal use
```

---

## Residual Risks That Cannot Be Fully Mitigated

These risks are inherent to the system's design and use case. No amount of hardening eliminates them entirely.

### 1. LLM Reasoning Manipulation

**Why it persists**: The Claude API must receive message content to perform useful reasoning. Any message content could contain adversarial text that influences the LLM's output.

**Affected phases**: All phases. Even Phase 5 (air gap) does not change the fact that Claude sees message content during queries.

**Partial mitigations**:
- System prompt hardening (instruct Claude to be skeptical of message content)
- Data minimization (send only top-K relevant messages, not entire history)
- Confidence scoring (flag low-confidence responses for human review)
- Multi-query verification (ask the same question in different ways)

**Residual risk level**: Medium. This is the single largest residual risk in the system.

### 2. Information Already in Context

**Why it persists**: Once messages are in the query database and the bot has SELECT access, the bot can surface any synced message in response to a query. There is no way to "un-know" data that has been synced.

**Partial mitigations**:
- Per-chat access controls (exclude certain chats from query results)
- Time-based expiry (auto-delete messages older than N days)
- Query audit logging (detect unusual access patterns)

**Residual risk level**: Low-Medium. The owner is querying their own data, so the primary risk is information surfacing in unexpected contexts.

### 3. Physical Device Compromise

**Why it persists**: An attacker with prolonged physical access to the Raspberry Pi can extract data through hardware attacks (JTAG, SD card removal, cold boot).

**Partial mitigations**:
- Full disk encryption (LUKS) with TPM-sealed key (Phase 4)
- Removable HSM that you carry with you (YubiHSM 2)
- Tamper-evident enclosure
- Phase 5 air gap (attacker must compromise BOTH machines)

**Residual risk level**: Low for most threat models. High if you face state-level adversaries.

### 4. Upstream Dependency Vulnerabilities

**Why it persists**: The system depends on Telethon, python-telegram-bot, sentence-transformers, asyncpg, the Claude API client, PostgreSQL, pgvector, the Linux kernel, and Python itself. A vulnerability in any of these could bypass application-level controls.

**Partial mitigations**:
- Pin all dependency versions
- Monitor CVE databases for critical vulnerabilities
- Minimize dependency count
- Use virtual environments to isolate Python packages
- Subscribe to security advisories for key dependencies

**Residual risk level**: Low. The dependency set is relatively small and well-maintained.

### 5. Telegram Policy Changes

**Why it persists**: Telegram may change their Terms of Service, rate limiting, or MTProto protocol in ways that break the syncer or result in account restrictions. This risk is entirely outside the operator's control.

**Partial mitigations**:
- Conservative rate limiting (well below observed thresholds)
- Human-like access patterns (randomized intervals, no burst traffic)
- Monitor Telegram developer channels for policy changes
- Maintain ability to switch to Bot API-only mode as fallback

**Residual risk level**: Medium. Cannot be eliminated through technical controls.

---

## Appendix: Phase Dependency Graph

Phases are largely independent. The recommended order is based on effort-to-value ratio, not technical dependencies.

```
Phase 1 (Local Embeddings) -----> independent
Phase 2 (Network Namespaces) ---> independent
Phase 3 (Encrypted DB) ---------> independent
Phase 4 (HSM/TPM) --------------> enhanced by Phase 3 (can store pgcrypto key in HSM too)
Phase 5 (Air Gap) --------------> benefits from Phase 1 (local embeddings on query machine)
                                   benefits from Phase 3 (encrypted export files)
                                   benefits from Phase 4 (HSM on sync machine)
```

Phase 5 benefits most from having Phases 1, 3, and 4 implemented first, but none are strict prerequisites. You can implement any phase independently based on your threat model.
