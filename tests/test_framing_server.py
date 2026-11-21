import os
import socket
import stat
import threading

import pytest
from kmssuite.common.framing import b64d, b64e, recv_msg, send_msg
from kmssuite.common.fsutil import atomic_write
from kmssuite.common.server import make_server


def test_atomic_write_permisos_y_reemplazo(tmp_path):
    p = tmp_path / "k.bin"
    atomic_write(p, b"uno")
    atomic_write(p, b"dos")
    assert p.read_bytes() == b"dos"
    if os.name == "posix":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    else:
        assert p.stat().st_mode & stat.S_IWRITE
    assert [f.name for f in tmp_path.iterdir()] == ["k.bin"]


def test_roundtrip_socketpair():
    a, b = socket.socketpair()
    send_msg(a, {"x": 1, "d": b64e(b"\x00\xff")})
    got = recv_msg(b)
    assert got["x"] == 1 and b64d(got["d"]) == b"\x00\xff"


def test_cierre_y_trama_invalida():
    a, b = socket.socketpair()
    a.close()
    with pytest.raises(ConnectionError):
        recv_msg(b)
    c, d = socket.socketpair()
    c.sendall(b"\xff\xff\xff\xff")
    with pytest.raises(ValueError):
        recv_msg(d)


def test_servidor_eco():
    def handle(sock, addr):
        send_msg(sock, recv_msg(sock))

    srv = make_server("127.0.0.1", 0, handle)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            send_msg(s, {"hola": "mundo"})
            assert recv_msg(s) == {"hola": "mundo"}
    finally:
        srv.shutdown()
        srv.server_close()
