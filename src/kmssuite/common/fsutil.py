"""Escritura atómica de archivos (compartida por Mini-KMS y Provisión)."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write(path: str | Path, data: bytes, mode: int = 0o600) -> None:
    """Escribe en un temporal del mismo directorio, fsync y os.replace (nunca deja un archivo a medias)."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
