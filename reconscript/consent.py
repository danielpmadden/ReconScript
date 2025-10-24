"""Consent manifest validation utilities."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from nacl import exceptions as nacl_exceptions
from nacl.signing import SigningKey, VerifyKey

SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "scope_manifest.v1.json"
DEV_KEYS_DIR = Path(__file__).resolve().parents[1] / "keys"


class ConsentError(ValueError):
    """Raised when a consent manifest fails validation."""


@dataclass(frozen=True)
class ConsentManifest:
    owner_name: str
    owner_email: str
    target: str
    allowed_ports: list[int]
    valid_from: datetime
    valid_until: datetime
    signature: str
    evidence_level: str | None = None

    @property
    def signer_display(self) -> str:
        return f"{self.owner_name} <{self.owner_email}>"


@dataclass
class ConsentValidationResult:
    manifest: ConsentManifest
    verify_key: VerifyKey


ISO_FORMATS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_iso8601(value: str) -> datetime:
    for fmt in ISO_FORMATS:
        try:
            return datetime.strptime(value, fmt).astimezone(timezone.utc)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:  # pragma: no cover - defensive branch
        raise ConsentError(f"Invalid timestamp '{value}' in manifest.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _allow_dev_secrets() -> bool:
    return os.environ.get("ALLOW_DEV_SECRETS", "false").lower() == "true"


def _guard_key_path(path: Path, *, env_var: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise ConsentError(f"{env_var} must point to an existing file (got {resolved}).")
    try:
        if DEV_KEYS_DIR in resolved.parents and not _allow_dev_secrets():
            raise ConsentError(
                f"{env_var} references developer sample keys. Provide production keys or set ALLOW_DEV_SECRETS=true for local testing."
            )
    except ConsentError:
        raise
    except Exception:
        pass
    return resolved


def _load_public_key(path: Path) -> VerifyKey:
    resolved = _guard_key_path(path, env_var="CONSENT_PUBLIC_KEY_PATH")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise ConsentError(f"Unable to read consent public key: {exc}") from exc
    return VerifyKey(raw)


def _load_private_key(path: Path) -> SigningKey:
    resolved = _guard_key_path(path, env_var="REPORT_SIGNING_KEY_PATH")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise ConsentError(f"Unable to read signing private key: {exc}") from exc
    return SigningKey(raw)


def _resolve_key_path(provided: Optional[Path], env_var: str) -> Path:
    if provided is not None:
        return _guard_key_path(provided, env_var=env_var)
    env_value = os.environ.get(env_var)
    if not env_value:
        raise ConsentError(f"{env_var} must be set to the path of the authorised signing key.")
    return _guard_key_path(Path(env_value), env_var=env_var)


def load_manifest(path: Path | str) -> ConsentManifest:
    try:
        content = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConsentError(f"Unable to read consent manifest: {exc}") from exc
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ConsentError("Consent manifest must be valid JSON.") from exc

    expected_fields = {
        "owner_name": str,
        "owner_email": str,
        "target": str,
        "allowed_ports": list,
        "valid_from": str,
        "valid_until": str,
        "signature": str,
    }
    missing = [field for field in expected_fields if field not in payload]
    if missing:
        raise ConsentError(f"Manifest missing required fields: {', '.join(missing)}")

    allowed_ports = payload.get("allowed_ports")
    if not isinstance(allowed_ports, list) or not all(
        isinstance(p, int) for p in allowed_ports
    ):
        raise ConsentError("allowed_ports must be a list of integers.")

    evidence_level = payload.get("evidence_level")
    if evidence_level is not None and evidence_level not in {"low", "medium", "high"}:
        raise ConsentError(
            "evidence_level must be one of low, medium, or high when provided."
        )

    manifest = ConsentManifest(
        owner_name=str(payload["owner_name"]).strip(),
        owner_email=str(payload["owner_email"]).strip(),
        target=str(payload["target"]).strip(),
        allowed_ports=[int(port) for port in allowed_ports],
        valid_from=_parse_iso8601(str(payload["valid_from"]).strip()),
        valid_until=_parse_iso8601(str(payload["valid_until"]).strip()),
        signature=str(payload["signature"]).strip(),
        evidence_level=evidence_level,
    )
    return manifest


def validate_manifest(
    manifest: ConsentManifest, *, public_key_path: Optional[Path] = None
) -> ConsentValidationResult:
    key_path = _resolve_key_path(public_key_path, "CONSENT_PUBLIC_KEY_PATH")
    verify_key = _load_public_key(key_path)

    body = {
        "owner_name": manifest.owner_name,
        "owner_email": manifest.owner_email,
        "target": manifest.target,
        "allowed_ports": manifest.allowed_ports,
        "valid_from": manifest.valid_from.replace(tzinfo=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "valid_until": manifest.valid_until.replace(tzinfo=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    if manifest.evidence_level:
        body["evidence_level"] = manifest.evidence_level

    try:
        signature_bytes = base64.b64decode(manifest.signature)
    except (ValueError, TypeError) as exc:
        raise ConsentError("Manifest signature is not valid base64.") from exc

    try:
        verify_key.verify(_canonical_json(body), signature_bytes)
    except (nacl_exceptions.BadSignatureError, ValueError) as exc:
        raise ConsentError("Consent manifest signature could not be verified.") from exc

    now = datetime.now(timezone.utc)
    if manifest.valid_from > now or manifest.valid_until < now:
        raise ConsentError(
            "Consent manifest is not currently valid based on validity window."
        )

    return ConsentValidationResult(manifest=manifest, verify_key=verify_key)


def sign_report_hash(
    report_hash: str, *, private_key_path: Optional[Path] = None
) -> bytes:
    key_path = _resolve_key_path(private_key_path, "REPORT_SIGNING_KEY_PATH")
    signing_key = _load_private_key(key_path)
    message = report_hash.encode("utf-8")
    signed = signing_key.sign(message)
    return signed.signature
