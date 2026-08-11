"""Regression tests for security Finding 2 (private disclosure): a server-supplied
org vault config (fetched from /org/vault-config, settable by an org admin) could
direct the client to ship a local secret to an attacker-chosen host — http://
endpoint (plaintext SigV4 Authorization header), or a file:/arbitrary-env access
key ref. load_driver now validates the config and falls back to local-only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import railcall_vault_drivers as VD


def _ok(cfg):
    return VD._validate_org_vault_config(cfg)[0]


def test_http_endpoint_rejected():
    assert _ok({"driver": "s3", "endpoint_url": "http://attacker/",
                "access_key_ref": "env:RAILCALL_VAULT_AK",
                "secret_key_ref": "env:RAILCALL_VAULT_SK"}) is False


def test_file_ref_rejected():
    assert _ok({"driver": "s3", "endpoint_url": "https://x/",
                "access_key_ref": "file:/home/u/.ssh/id_rsa",
                "secret_key_ref": "env:RAILCALL_VAULT_SK"}) is False


def test_arbitrary_env_ref_rejected():
    assert _ok({"driver": "s3", "endpoint_url": "https://x/",
                "access_key_ref": "env:AWS_SECRET_ACCESS_KEY",
                "secret_key_ref": "env:RAILCALL_VAULT_SK"}) is False


def test_unknown_driver_rejected():
    assert _ok({"driver": "railcall_exfil"}) is False


def test_custom_driver_needs_local_optin(monkeypatch):
    monkeypatch.delenv("RAILCALL_ORG_VAULT_ALLOW_CUSTOM", raising=False)
    assert _ok({"driver": "custom", "module_ref": "evil"}) is False
    monkeypatch.setenv("RAILCALL_ORG_VAULT_ALLOW_CUSTOM", "1")
    assert _ok({"driver": "custom", "module_ref": "myorg.vault"}) is True


def test_legit_https_prefixed_env_allowed():
    assert _ok({"driver": "s3", "endpoint_url": "https://s3.eu-west-1.amazonaws.com",
                "access_key_ref": "env:RAILCALL_VAULT_AK",
                "secret_key_ref": "env:RAILCALL_VAULT_SK"}) is True


def test_local_and_default_endpoint_allowed():
    assert _ok({"driver": "local", "path": "/mnt/vault"}) is True
    assert _ok({"driver": "s3", "region": "us-east-1",
                "access_key_ref": "keyring:aws", "secret_key_ref": "keyring:aws"}) is True


def test_load_driver_refuses_malicious_config():
    # The chokepoint returns a NullVaultDriver (local-only) — never builds S3.
    d = VD.load_driver({"driver": "s3", "endpoint_url": "http://attacker/",
                        "access_key_ref": "file:/etc/passwd", "secret_key_ref": "env:X"})
    assert type(d).__name__ == "NullVaultDriver"
