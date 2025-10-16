#!/usr/bin/env python3
"""Utility to generate and sign scope manifests for ReconScript."""

from __future__ import annotations

import argparse
import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from nacl.signing import SigningKey

DEFAULT_KEY = Path("keys/dev_ed25519.priv")


def _canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_ports(values: Sequence[str]) -> list[int]:
    ports: list[int] = []
    for value in values:
        port = int(value)
        if port <= 0 or port > 65535:
            raise ValueError("Port values must be between 1 and 65535")
        ports.append(port)
    return ports


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate signed scope manifest for ReconScript.")
    parser.add_argument("--owner-name", required=True)
    parser.add_argument("--owner-email", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--ports", nargs="+", required=True, help="Approved ports")
    parser.add_argument("--valid-days", type=int, default=7, help="Validity window in days")
    parser.add_argument("--key", type=Path, default=DEFAULT_KEY, help="Path to ed25519 private key")
    parser.add_argument("--evidence-level", choices=("low", "medium", "high"), default="low")
    parser.add_argument("--output", type=Path, default=Path("manifest.json"))
    args = parser.parse_args()

    key_bytes = args.key.read_bytes()
    signing_key = SigningKey(key_bytes)

    now = datetime.now(timezone.utc)
    body = {
        "owner_name": args.owner_name,
        "owner_email": args.owner_email,
        "target": args.target,
        "allowed_ports": _parse_ports(args.ports),
        "valid_from": now.isoformat().replace("+00:00", "Z"),
        "valid_until": (now + timedelta(days=args.valid_days)).isoformat().replace("+00:00", "Z"),
        "evidence_level": args.evidence_level,
    }
    payload = {**body}
    signature = signing_key.sign(_canonical_json(body)).signature
    payload["signature"] = base64.b64encode(signature).decode("ascii")

    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Manifest written to {args.output}")


if __name__ == "__main__":
    main()
