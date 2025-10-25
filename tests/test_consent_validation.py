from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from nacl.signing import SigningKey
from reconscript.consent import ConsentError, load_manifest, validate_manifest


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_manifest(tmp_path: Path, body: dict) -> Path:
    private_key = Path(os.environ["REPORT_SIGNING_KEY_PATH"])  # set by tests fixture
    signing_key = SigningKey(private_key.read_bytes())
    signed = signing_key.sign(_canonical(body)).signature
    payload = {**body, "signature": base64.b64encode(signed).decode("ascii")}
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    return manifest_path


def test_manifest_validation_roundtrip(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    body = {
        "owner_name": "Example Owner",
        "owner_email": "owner@example.com",
        "target": "127.0.0.1",
        "allowed_ports": [80, 443],
        "valid_from": now.isoformat().replace("+00:00", "Z"),
        "valid_until": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "evidence_level": "high",
    }
    manifest_path = _write_manifest(tmp_path, body)
    manifest = load_manifest(manifest_path)
    result = validate_manifest(manifest)
    assert result.manifest.owner_name == "Example Owner"


def test_invalid_signature_rejected(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    body = {
        "owner_name": "Bad Actor",
        "owner_email": "bad@example.com",
        "target": "192.0.2.1",
        "allowed_ports": [80],
        "valid_from": now.isoformat().replace("+00:00", "Z"),
        "valid_until": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
    }
    manifest_path = _write_manifest(tmp_path, body)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["signature"] = base64.b64encode(b"tampered").decode("ascii")
    manifest_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ConsentError):
        manifest = load_manifest(manifest_path)
        validate_manifest(manifest)
