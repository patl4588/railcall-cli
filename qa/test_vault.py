import unittest
import os
import json
import sys

# Add repo root and vault to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from vault import vault


class TestVault(unittest.TestCase):
    def setUp(self):
        # Override the vault path for tests to avoid touching user's real ~/.railcall
        self.orig_vault_path = vault.VAULT_PATH
        vault.VAULT_PATH = os.path.abspath("test_keys.local.json")
        if os.path.exists(vault.VAULT_PATH):
            try:
                os.remove(vault.VAULT_PATH)
            except OSError:
                pass
        # Reset internal states
        vault._unlocked_keys = {}
        vault._is_locked = True
        vault._current_passphrase = None

    def tearDown(self):
        if os.path.exists(vault.VAULT_PATH):
            try:
                os.remove(vault.VAULT_PATH)
            except OSError:
                pass
        vault.VAULT_PATH = self.orig_vault_path

    def test_vault_flow(self):
        fixture_keys = {"my_key": "super_secret_value"}
        
        # 1. Start with no file (should be unlocked / empty)
        self.assertFalse(vault.is_locked())
        
        # 2. populate keys and lock/rotate with a passphrase
        vault._unlocked_keys = fixture_keys
        vault._is_locked = False
        
        passphrase = "my_secure_passphrase"
        vault.rotate(passphrase)
        
        # 3. Assert on-disk bytes are ciphertext, not plaintext JSON
        self.assertTrue(os.path.exists(vault.VAULT_PATH))
        with open(vault.VAULT_PATH, "r", encoding="utf-8") as f:
            raw = f.read()
            # Must not contain secret data in plaintext
            self.assertNotIn("super_secret_value", raw)
            self.assertNotIn("my_key", raw)
            # Must be JSON payload with _encrypted=True
            data = json.loads(raw)
            self.assertTrue(data.get("_encrypted"))
            
        # Reset memory state
        vault._unlocked_keys = {}
        vault._is_locked = True
        
        # 4. Assert locked
        self.assertTrue(vault.is_locked())
        self.assertIsNone(vault.read_key("my_key"))
        
        # 5. Unlock with wrong passphrase (fails closed, returns False)
        ok = vault.unlock("wrong_passphrase")
        self.assertFalse(ok)
        self.assertTrue(vault.is_locked())
        self.assertIsNone(vault.read_key("my_key"))
        
        # 6. Unlock with correct passphrase
        ok = vault.unlock(passphrase)
        self.assertTrue(ok)
        self.assertFalse(vault.is_locked())
        self.assertEqual(vault.read_key("my_key"), "super_secret_value")


if __name__ == "__main__":
    unittest.main()
