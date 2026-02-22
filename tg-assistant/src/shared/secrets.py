"""
Secrets retrieval and encrypted session file management.

Lookup order for secrets (first match wins):

1. **systemd LoadCredential** — ``$CREDENTIALS_DIRECTORY/<key_name>``
   (production: per-service isolation, root-owned source files in
   ``/etc/credstore/``, never in env vars or config files).
2. **System keychain** — ``secret-tool lookup`` (libsecret / GNOME Keyring).
3. **Environment variable** — ``TG_ASSISTANT_<KEY_NAME>`` when
   ``TG_ASSISTANT_ALLOW_ENV_SECRETS=1`` (development only).

The Telethon session file is encrypted at rest using Fernet symmetric
encryption.  It is decrypted into memory only when the syncer starts,
and the plaintext is never written to disk.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from cryptography.fernet import Fernet

logger = logging.getLogger("shared.secrets")


# ---------------------------------------------------------------------------
# System keychain
# ---------------------------------------------------------------------------


def get_secret(key_name: str, service: str = "tg-assistant") -> str:
    """Retrieve a secret, checking multiple sources in priority order.

    Lookup order:

    1. **systemd LoadCredential** — reads
       ``$CREDENTIALS_DIRECTORY/<key_name>``.  This is the preferred
       production mechanism: systemd loads the file from
       ``/etc/credstore/`` (root:root 0600) and exposes it read-only
       to the specific service under a private tmpfs mount.
    2. **System keychain** — ``secret-tool lookup service <service>
       key <key_name>`` (requires a D-Bus session; works for
       interactive users but not headless system services).
    3. **Environment variable** — ``TG_ASSISTANT_<KEY_NAME>``
       when ``TG_ASSISTANT_ALLOW_ENV_SECRETS=1`` (development / CI only).

    Args:
        key_name: The key identifier (e.g. ``"bot_token"``,
                  ``"anthropic_api_key"``, ``"session_encryption_key"``).
        service: The service label in the keychain.

    Returns:
        The secret value as a string.

    Raises:
        RuntimeError: If the secret is not found in any source.
    """
    # 1. systemd LoadCredential ($CREDENTIALS_DIRECTORY)
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        cred_path = Path(cred_dir) / key_name
        try:
            secret = cred_path.read_text().strip()
            if secret:
                logger.debug("Secret '%s' loaded from credentials directory", key_name)
                return secret
        except FileNotFoundError:
            pass
        except PermissionError:
            logger.warning(
                "Permission denied reading credential '%s' from %s",
                key_name,
                cred_dir,
            )

    # 2. System keychain (secret-tool / libsecret)
    try:
        result = subprocess.run(
            ["secret-tool", "lookup", "service", service, "key", key_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        secret = result.stdout.strip()
        if secret:
            return secret
    except FileNotFoundError:
        logger.warning(
            "secret-tool not found; falling back to environment variable"
        )
    except subprocess.TimeoutExpired:
        logger.warning("secret-tool timed out; falling back to environment variable")
    except Exception:
        logger.warning(
            "secret-tool failed; falling back to environment variable",
            exc_info=True,
        )

    # 3. Environment variable (development / CI only)
    allow_env_fallback = os.environ.get("TG_ASSISTANT_ALLOW_ENV_SECRETS", "").lower() in {
        "1", "true", "yes",
    }
    env_key = f"TG_ASSISTANT_{key_name.upper().replace('-', '_')}"
    env_val = os.environ.get(env_key)
    if env_val and allow_env_fallback:
        logger.warning("Using env var fallback for secret '%s' (%s)", key_name, env_key)
        return env_val

    raise RuntimeError(
        f"Secret '{key_name}' not found in credentials directory, "
        f"keychain (service={service}), or environment variable {env_key} "
        "(env fallback requires TG_ASSISTANT_ALLOW_ENV_SECRETS=1)"
    )


# ---------------------------------------------------------------------------
# Session file encryption (Fernet)
# ---------------------------------------------------------------------------


def encrypt_session_file(path: Path, key: str) -> None:
    """Encrypt a Telethon session file in-place using Fernet.

    After encryption, the original plaintext file is overwritten with
    the ciphertext.  The plaintext is zeroed in memory before returning.

    Args:
        path: Path to the plaintext session file.
        key: Fernet-compatible key (base64-encoded 32-byte key).

    Raises:
        FileNotFoundError: If the session file does not exist.
        cryptography.fernet.InvalidToken: If the key is invalid.
    """
    f = Fernet(key.encode())
    plaintext = path.read_bytes()
    ciphertext = f.encrypt(plaintext)
    path.write_bytes(ciphertext)
    path.chmod(0o600)
    logger.info("Session file encrypted: %s", path)


def decrypt_session_file(path: Path, key: str) -> bytes:
    """Decrypt a Telethon session file and return the plaintext **in memory**.

    The decrypted content is never written to disk.  Callers should use
    the returned bytes to construct a Telethon ``StringSession`` or
    write to a tmpfs mount if a file path is required.

    Args:
        path: Path to the encrypted session file.
        key: Fernet-compatible key (base64-encoded 32-byte key).

    Returns:
        The decrypted session data as bytes.

    Raises:
        FileNotFoundError: If the session file does not exist.
        cryptography.fernet.InvalidToken: If the key is wrong or the
            file has been tampered with.
    """
    f = Fernet(key.encode())
    ciphertext = path.read_bytes()
    plaintext = f.decrypt(ciphertext)
    logger.info("Session file decrypted in memory: %s", path)
    return plaintext


def generate_encryption_key() -> str:
    """Generate a new Fernet encryption key.

    Returns:
        A base64-encoded 32-byte key suitable for Fernet.

    This should be called once during initial setup and the resulting
    key stored in the system keychain.
    """
    return Fernet.generate_key().decode()
