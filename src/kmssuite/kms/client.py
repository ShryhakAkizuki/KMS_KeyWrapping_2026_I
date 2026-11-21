"""Cliente del Mini-KMS."""
from __future__ import annotations

import socket

from kmssuite.common.config import env, env_int
from kmssuite.common.framing import b64d, b64e, recv_msg, send_msg


class KmsRemoteError(Exception):
    """El servidor respondió ok=false."""


class KmsClient:
    def __init__(self, host: str, port: int, token: str, timeout: float = 30.0):
        self.host, self.port, self.token, self.timeout = host, port, token, timeout

    @classmethod
    def from_env(cls) -> "KmsClient":
        return cls(env("KMS_HOST", "127.0.0.1"), env_int("KMS_PORT", 9001), env("KMS_TOKEN", required=True))

    def _call(self, req: dict) -> dict:
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            send_msg(sock, {**req, "token": self.token})
            resp = recv_msg(sock)
        if not resp.get("ok"):
            raise KmsRemoteError(resp.get("error", "error desconocido"))
        return resp

    def put(self, obj_id: str, data: bytes, overwrite: bool = False) -> str:
        return self._call({"op": "put", "id": obj_id, "data": b64e(data), "overwrite": overwrite})["id"]

    def get(self, obj_id: str) -> bytes:
        return b64d(self._call({"op": "get", "id": obj_id})["data"])

    def rotate(self) -> int:
        return self._call({"op": "rotate"})["active_version"]

    def list(self) -> list[dict]:
        return self._call({"op": "list"})["objects"]

    def status(self) -> dict:
        resp = self._call({"op": "status"})
        return {k: v for k, v in resp.items() if k != "ok"}
