"""HMAC_DRBG (NIST SP 800-90A) con SHA-256, sembrado desde os.urandom."""
from __future__ import annotations

import hashlib
import hmac
import os
import threading

_RESEED_INTERVAL = 1 << 20     # llamadas a generate antes de reseed forzado
_MAX_REQUEST = 1 << 16         # bytes máximos por llamada


class HmacDrbg:
    def __init__(self, seed: bytes | None = None, personalization: bytes = b""):
        if seed is None:
            seed = os.urandom(48)
        if len(seed) < 32:
            raise ValueError("la semilla debe tener al menos 32 bytes")
        self._k = b"\x00" * 32
        self._v = b"\x01" * 32
        self._lock = threading.Lock()
        self._update(seed + personalization)
        self._counter = 1

    @staticmethod
    def _hmac(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def _update(self, data: bytes = b"") -> None:
        self._k = self._hmac(self._k, self._v + b"\x00" + data)
        self._v = self._hmac(self._k, self._v)
        if data:
            self._k = self._hmac(self._k, self._v + b"\x01" + data)
            self._v = self._hmac(self._k, self._v)

    def reseed(self, entropy: bytes | None = None, additional: bytes = b"") -> None:
        if entropy is None:
            entropy = os.urandom(32)
        with self._lock:
            self._update(entropy + additional)
            self._counter = 1

    def generate(self, n: int, additional: bytes = b"") -> bytes:
        if not 0 < n <= _MAX_REQUEST:
            raise ValueError("tamaño solicitado fuera de rango")
        with self._lock:
            if self._counter > _RESEED_INTERVAL:
                self._update(os.urandom(32))
                self._counter = 1
            if additional:
                self._update(additional)
            out = b""
            while len(out) < n:
                self._v = self._hmac(self._k, self._v)
                out += self._v
            self._update(additional)
            self._counter += 1
            return out[:n]


_default: HmacDrbg | None = None
_default_lock = threading.Lock()


def get_drbg() -> HmacDrbg:
    global _default
    with _default_lock:
        if _default is None:
            _default = HmacDrbg()
        return _default


def random_bytes(n: int) -> bytes:
    return get_drbg().generate(n)
