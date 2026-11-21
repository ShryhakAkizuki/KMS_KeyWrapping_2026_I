"""Servidor TCP con un hilo por conexión. handle(sock, addr) contiene la lógica del servicio."""
from __future__ import annotations

import logging
import socketserver
from typing import Callable

log = logging.getLogger("kmssuite.server")


def make_server(host: str, port: int, handle: Callable, timeout: float = 30.0):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(timeout)
            try:
                handle(self.request, self.client_address)
            except (ConnectionError, TimeoutError, ValueError, KeyError) as exc:
                log.warning("conexión %s terminada: %s", self.client_address, type(exc).__name__)
            except Exception:
                log.exception("error inesperado atendiendo %s", self.client_address)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    return Server((host, port), Handler)


def serve_forever(host: str, port: int, handle: Callable) -> None:
    with make_server(host, port, handle) as srv:
        log.info("escuchando en %s:%s", host, port)
        srv.serve_forever()
