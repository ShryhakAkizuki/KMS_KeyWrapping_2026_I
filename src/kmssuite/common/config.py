"""Lectura de configuración desde variables de entorno."""
from __future__ import annotations

import os


def env(name: str, default: str | None = None, required: bool = False) -> str | None:
    value = os.environ.get(name, default)
    if required and (value is None or value == ""):
        raise RuntimeError(f"Falta la variable de entorno {name}")
    return value


def env_int(name: str, default: int) -> int:
    return int(env(name, str(default)))
