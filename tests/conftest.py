import os
import sys
from pathlib import Path

import pytest

from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _secure_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("ALLOW_DEV_SECRETS", "true")
    seed = os.urandom(32)
    signing_key = SigningKey(seed)
    private_key_path = tmp_path / "report_signing.key"
    private_key_path.write_bytes(seed)
    public_key_path = tmp_path / "consent_verify.key"
    public_key_path.write_bytes(signing_key.verify_key.encode())
    monkeypatch.setenv("CONSENT_PUBLIC_KEY_PATH", str(public_key_path))
    monkeypatch.setenv("REPORT_SIGNING_KEY_PATH", str(private_key_path))
    monkeypatch.setenv("FLASK_SECRET_KEY", "unit-test-secret")
    monkeypatch.setenv("ADMIN_USER", "test-admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-password-123")
    yield
