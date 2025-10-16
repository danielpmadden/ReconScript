from __future__ import annotations

from reconscript.report import compute_report_hash


def test_report_hash_is_stable_with_key_order() -> None:
    payload_one = {
        "target": "127.0.0.1",
        "open_ports": [80],
        "metadata": {"foo": "bar", "baz": "qux"},
    }
    payload_two = {
        "metadata": {"baz": "qux", "foo": "bar"},
        "open_ports": [80],
        "target": "127.0.0.1",
        "report_hash": "placeholder",
    }

    hash_one = compute_report_hash(payload_one)
    hash_two = compute_report_hash(payload_two)
    assert hash_one == hash_two
