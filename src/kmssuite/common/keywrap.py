from __future__ import annotations

from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)


class IntegrityError(Exception):
    """Fallo de integridad: ICV, tag GCM o MIC inválidos. Siempre se rechaza."""


def wrap_key(kek: bytes, key: bytes) -> bytes:
    if len(kek) not in (16, 24, 32):
        raise ValueError("la KEK debe medir 16, 24 o 32 bytes")
    if len(key) < 16 or len(key) % 8 != 0:
        raise ValueError("la clave a envolver debe medir >=16 bytes y ser múltiplo de 8")
    return aes_key_wrap(kek, key)


def unwrap_key(kek: bytes, wrapped: bytes) -> bytes:
    if len(kek) not in (16, 24, 32):
        raise ValueError("la KEK debe medir 16, 24 o 32 bytes")
    try:
        return aes_key_unwrap(kek, wrapped)
    except InvalidUnwrap as exc:
        raise IntegrityError("ICV inválido: clave alterada o KEK incorrecta") from exc
