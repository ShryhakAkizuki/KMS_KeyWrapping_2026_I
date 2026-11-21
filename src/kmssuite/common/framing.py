"""Trama = 4 bytes longitud (big-endian) + JSON UTF-8. Binarios en base64."""
from __future__ import annotations

import base64
import json
import socket
import struct

MAX_FRAME = 64 * 1024 * 1024


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def send_msg(sock: socket.socket, obj: dict) -> None:
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise ValueError("trama demasiado grande")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("conexión cerrada por el otro extremo")
        buf += chunk
    return bytes(buf)


def recv_msg(sock: socket.socket) -> dict:
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    if length > MAX_FRAME:
        raise ValueError("trama demasiado grande")
    obj = json.loads(recv_exact(sock, length).decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("la trama debe ser un objeto JSON")
    return obj
