import os
import json
import tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from typing import Optional

VAULT_PATH = os.path.expanduser("~/.railcall/keys.local.json")

# In-memory store for unlocked keys
_unlocked_keys = {}
_is_locked = True
_current_passphrase = None


def _get_vault_path() -> str:
    d = os.path.dirname(VAULT_PATH)
    if d and not os.path.exists(d):
        return "keys.local.json"
    return VAULT_PATH


def is_locked() -> bool:
    """True if keys.local.json is encrypted at rest and not yet unlocked this session."""
    global _is_locked
    path = _get_vault_path()
    if not os.path.exists(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get("_encrypted") is True:
            return _is_locked
    except Exception:
        pass
    return False


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key with scrypt via `cryptography` (already a dependency here for AES-GCM).
    The stdlib hashlib.scrypt needs a Python built against OpenSSL's scrypt and is ABSENT on some
    platforms (e.g. stock macOS python), which broke the vault there; this path is portable and RFC
    7914-identical, so a vault sealed on one OS unlocks on another with the same params."""
    return Scrypt(salt=salt, length=32, n=16384, r=8, p=1).derive(passphrase.encode("utf-8"))


def unlock(passphrase: str) -> bool:
    """Derive the key and open the vault. Fail CLOSED on wrong passphrase."""
    global _unlocked_keys, _is_locked, _current_passphrase
    path = _get_vault_path()
    if not os.path.exists(path):
        _unlocked_keys = {}
        _is_locked = False
        return True

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False

    if not (isinstance(data, dict) and data.get("_encrypted") is True):
        # Plaintext on disk
        _unlocked_keys = data
        _is_locked = False
        _current_passphrase = None
        return True

    try:
        salt = bytes.fromhex(data["salt_hex"])
        nonce = bytes.fromhex(data["nonce_hex"])
        ciphertext = bytes.fromhex(data["ciphertext_hex"])
        
        key = _derive_key(passphrase, salt)
        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        _unlocked_keys = json.loads(decrypted_bytes.decode("utf-8"))
        _is_locked = False
        _current_passphrase = passphrase
        return True
    except Exception:
        return False


def read_key(name: str) -> Optional[str]:
    """Return a decrypted secret by name for the caller, in memory only. None if absent."""
    if is_locked():
        return None
    return _unlocked_keys.get(name)


def rotate(new_passphrase: str) -> None:
    """Re-encrypt at rest under a new passphrase."""
    global _unlocked_keys, _is_locked, _current_passphrase
    if is_locked():
        raise RuntimeError("Cannot rotate keys while vault is locked.")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    
    key = _derive_key(new_passphrase, salt)
    aesgcm = AESGCM(key)
    
    plaintext_bytes = json.dumps(_unlocked_keys, indent=2).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    payload = {
        "_encrypted": True,
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex()
    }
    
    path = _get_vault_path()
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    
    fd, tmp = tempfile.mkstemp(prefix=".keys-", suffix=".tmp", dir=directory)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(payload, indent=2).encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        if hasattr(os, "chmod"):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        _is_locked = False
        _current_passphrase = new_passphrase
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
