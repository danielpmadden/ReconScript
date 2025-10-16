"""Pure Python ed25519 signing compatible with PyNaCl subset."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Tuple

from .exceptions import BadSignatureError

# Curve constants
_b = 256
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493
def _inv(value: int) -> int:
    return pow(value, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)

# Base point (from RFC 8032)
_Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_By = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_B = (_Bx % _q, _By % _q)


@dataclass
class SignedMessage:
    signature: bytes
    message: bytes


# Utility functions ---------------------------------------------------------

def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _encode_int(n: int) -> bytes:
    return n.to_bytes(32, "little")


def _decode_int(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _recover_x(y: int) -> int:
    yy = (y * y) % _q
    u = (yy - 1) % _q
    v = (_d * yy + 1) % _q
    inv_v = _inv(v)
    xx = (u * inv_v) % _q
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


def _is_on_curve(P: Tuple[int, int]) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _encode_point(P: Tuple[int, int]) -> bytes:
    x, y = P
    bits = bytearray(_encode_int(y))
    bits[31] = (bits[31] & 0x7F) | ((x & 1) << 7)
    return bytes(bits)


def _decode_point(s: bytes) -> Tuple[int, int]:
    if len(s) != 32:
        raise BadSignatureError("encoded point must be 32 bytes")
    y = _decode_int(s) & ((1 << 255) - 1)
    x_sign = (s[31] >> 7) & 1
    if y >= _q:
        raise BadSignatureError("encoded y out of range")
    x = _recover_x(y)
    if x & 1 != x_sign:
        x = _q - x
    P = (x, y)
    if not _is_on_curve(P):
        raise BadSignatureError("point not on curve")
    return P


def _edwards_add(P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
    (x1, y1) = P
    (x2, y2) = Q
    product = (x1 * x2 * y1 * y2) % _q
    denom = _inv((1 + _d * product) % _q)
    denom_y = _inv((1 - _d * product) % _q)
    x3 = ((x1 * y2 + x2 * y1) % _q) * denom % _q
    y3 = ((y1 * y2 + x1 * x2) % _q) * denom_y % _q
    return (x3, y3)


def _edwards_double(P: Tuple[int, int]) -> Tuple[int, int]:
    return _edwards_add(P, P)


def _scalarmult(P: Tuple[int, int], e: int) -> Tuple[int, int]:
    Q = (0, 1)
    addend = P
    while e:
        if e & 1:
            Q = _edwards_add(Q, addend)
        addend = _edwards_double(addend)
        e >>= 1
    return Q


def _hint(data: bytes) -> int:
    return _decode_int(_sha512(data)) % _l


class VerifyKey:
    """Verify ed25519 signatures."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("VerifyKey must be created from 32 raw bytes")
        self._key = bytes(key)
        self._point = _decode_point(self._key)

    def verify(self, message: bytes, signature: bytes) -> bytes:
        if len(signature) != 64:
            raise BadSignatureError("signature must be 64 bytes")
        R = _decode_point(signature[:32])
        S = _decode_int(signature[32:])
        if S >= _l:
            raise BadSignatureError("signature scalar out of range")
        h = _hint(signature[:32] + self._key + message)
        left = _scalarmult(_B, S)
        right = _edwards_add(R, _scalarmult(self._point, h))
        if left != right:
            raise BadSignatureError("signature mismatch")
        return message

    def __bytes__(self) -> bytes:  # pragma: no cover - convenience
        return self._key


class SigningKey:
    """Create and verify ed25519 signatures from a seed."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("SigningKey seed must be 32 bytes")
        self._seed = bytes(seed)
        digest = _sha512(self._seed)
        a_bytes = bytearray(digest[:32])
        a_bytes[0] &= 248
        a_bytes[31] &= 127
        a_bytes[31] |= 64
        self._scalar = _decode_int(bytes(a_bytes)) % _l
        self._prefix = digest[32:]
        self._verify_key = VerifyKey(_encode_point(_scalarmult(_B, self._scalar)))

    @property
    def verify_key(self) -> VerifyKey:
        return self._verify_key

    def sign(self, message: bytes) -> SignedMessage:
        r = _hint(self._prefix + message)
        R = _encode_point(_scalarmult(_B, r))
        h = _hint(R + bytes(self._verify_key) + message)
        S = (r + h * self._scalar) % _l
        signature = R + _encode_int(S)
        return SignedMessage(signature=signature, message=message)
