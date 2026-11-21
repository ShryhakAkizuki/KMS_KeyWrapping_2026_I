"""Servicio Mini-KMS por TCP. Variables: KMS_DATA_DIR, KMS_TOKEN, KMS_PORT, KMS_BIND, PRF_NAME."""
from __future__ import annotations

import hmac
import logging

from kmssuite.common.config import env, env_int
from kmssuite.common.framing import b64d, b64e, recv_msg, send_msg
from kmssuite.common.keywrap import IntegrityError
from kmssuite.common.server import serve_forever
from kmssuite.kms.core import KmsError, MiniKms

log = logging.getLogger("kmssuite.kms")


def make_handler(kms: MiniKms, token: str):
    def handle(sock, addr):
        req = recv_msg(sock)
        if not hmac.compare_digest(str(req.get("token", "")).encode(), token.encode()):
            log.warning("token inválido desde %s", addr)
            send_msg(sock, {"ok": False, "error": "no autorizado"})
            return
        op = req.get("op")
        try:
            if op == "put":
                kms.put(req["id"], b64d(req["data"]), overwrite=bool(req.get("overwrite")))
                send_msg(sock, {"ok": True, "id": req["id"]})
            elif op == "get":
                send_msg(sock, {"ok": True, "data": b64e(kms.get(req["id"]))})
            elif op == "rotate":
                send_msg(sock, {"ok": True, "active_version": kms.rotate()})
            elif op == "list":
                send_msg(sock, {"ok": True, "objects": kms.list_objects()})
            elif op == "status":
                send_msg(sock, {"ok": True, **kms.status()})
            else:
                send_msg(sock, {"ok": False, "error": "operación desconocida"})
        except KmsError as exc:
            send_msg(sock, {"ok": False, "error": str(exc)})
        except IntegrityError:
            log.warning("FALLO DE INTEGRIDAD en id=%s", req.get("id"))
            send_msg(sock, {"ok": False, "error": "integridad"})
        except (KeyError, ValueError):
            send_msg(sock, {"ok": False, "error": "petición inválida"})

    return handle


def main() -> None:
    logging.basicConfig(level=env("LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(message)s")
    kms = MiniKms(env("KMS_DATA_DIR", required=True), prf_name=env("PRF_NAME", "hmac-sha256"))
    token = env("KMS_TOKEN", required=True)
    serve_forever(env("KMS_BIND", "0.0.0.0"), env_int("KMS_PORT", 9001), make_handler(kms, token))


if __name__ == "__main__":
    main()
