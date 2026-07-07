# Vault interface (T3) — the contract you build to

The engine/CLI calls a tiny, documented interface. You implement it; you never see the engine. Keep the surface exactly this so it drops in.

```python
# vault/vault.py  (you build this)

def is_locked() -> bool:
    """True if keys.local.json is encrypted at rest and not yet unlocked this session."""

def unlock(passphrase: str) -> bool:
    """Derive the key (Argon2id or scrypt) and open the vault. Fail CLOSED on wrong
    passphrase — return False, never raise a plaintext hint. No key material to disk/logs."""

def read_key(name: str) -> str | None:
    """Return a decrypted secret by name for the caller, in memory only. None if absent."""

def rotate(new_passphrase: str) -> None:
    """Re-encrypt at rest under a new passphrase. Old ciphertext unrecoverable after."""
```

## Requirements
- **AES-256-GCM** at rest; KDF = Argon2id (preferred) or scrypt, per-vault random salt + nonce.
- `keys.local.json` on disk is **ciphertext** whenever `is_locked()` — verify with `xxd`.
- **Zero plaintext** key ever written to disk or logs, even transiently.
- Optional OS-keychain unlock (macOS Keychain / libsecret) as an alternative to the passphrase.
- A signed test receipt must still verify end-to-end after a lock → unlock cycle.

## Acceptance test to include
`qa/test_vault.py`: encrypt a fixture key → assert on-disk bytes are not the plaintext → unlock → `read_key` returns it → wrong passphrase returns False and reveals nothing.
