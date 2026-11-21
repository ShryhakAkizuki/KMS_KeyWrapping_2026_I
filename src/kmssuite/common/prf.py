"""PRFs/KDFs intercambiables. Firma común: derive(name, key, label, context, length)."""
from __future__ import annotations

import hashlib
import hmac
import math
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _counter_prf(hash_ctor):
    digest_size = hash_ctor().digest_size

    def prf(key: bytes, label: bytes, context: bytes, length: int) -> bytes:
        blocks = math.ceil(length / digest_size)
        if length <= 0 or blocks > 255:
            raise ValueError("longitud de salida fuera de rango")
        out = b"".join(
            hmac.new(key, label + b"\x00" + context + bytes([i]), hash_ctor).digest()
            for i in range(blocks)
        )
        return out[:length]

    return prf


def _hkdf_sha256(key: bytes, label: bytes, context: bytes, length: int) -> bytes:
    if length <= 0 or length > 255 * 32:
        raise ValueError("longitud de salida fuera de rango")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=label, info=context).derive(key)


PRFS: dict[str, Callable[[bytes, bytes, bytes, int], bytes]] = {
    "hmac-sha1": _counter_prf(hashlib.sha1),
    "hmac-sha256": _counter_prf(hashlib.sha256),
    "hkdf-sha256": _hkdf_sha256,
}


def derive(name: str, key: bytes, label: bytes, context: bytes, length: int) -> bytes:
    try:
        fn = PRFS[name]
    except KeyError:
        raise ValueError(f"PRF desconocida: {name}. Opciones: {sorted(PRFS)}") from None
    return fn(key, label, context, length)
