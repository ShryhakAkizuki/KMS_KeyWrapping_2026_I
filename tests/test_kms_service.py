import threading

import pytest
from kmssuite.common.server import make_server
from kmssuite.kms.client import KmsClient, KmsRemoteError
from kmssuite.kms.core import MiniKms
from kmssuite.kms.server import make_handler


@pytest.fixture()
def service(tmp_path):
    kms = MiniKms(tmp_path)
    srv = make_server("127.0.0.1", 0, make_handler(kms, "tok123"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield KmsClient("127.0.0.1", srv.server_address[1], "tok123", timeout=5), tmp_path
    srv.shutdown()
    srv.server_close()


def test_put_get_list_status(service):
    c, _ = service
    c.put("doc", b"contenido")
    assert c.get("doc") == b"contenido"
    assert c.list()[0]["id"] == "doc"
    assert c.status()["active_version"] == 1


def test_rotacion_por_red(service):
    c, _ = service
    c.put("doc", b"x")
    assert c.rotate() == 2
    assert c.get("doc") == b"x"
    assert c.list()[0]["kek_version"] == 2


def test_token_incorrecto(service):
    c, _ = service
    bad = KmsClient(c.host, c.port, "otro", timeout=5)
    with pytest.raises(KmsRemoteError, match="no autorizado"):
        bad.status()


def test_errores_de_uso(service):
    c, _ = service
    with pytest.raises(KmsRemoteError):
        c.get("no-existe")
    with pytest.raises(KmsRemoteError):
        c.put("../malo", b"x")


def test_integridad_no_filtra_detalles(service):
    c, tmp = service
    c.put("doc", b"x" * 50)
    p = tmp / "objects" / "doc.bin"
    raw = bytearray(p.read_bytes()); raw[15] ^= 1; p.write_bytes(bytes(raw))
    with pytest.raises(KmsRemoteError, match="^integridad$"):
        c.get("doc")
