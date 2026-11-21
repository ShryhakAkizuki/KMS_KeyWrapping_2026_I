import hashlib
import json
import os
import stat

import pytest
from kmssuite.common.keywrap import IntegrityError
from kmssuite.kms.core import KmsError, MiniKms


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_roundtrip(tmp_path):
    k = MiniKms(tmp_path)
    k.put("a.txt", b"secreto")
    assert k.get("a.txt") == b"secreto"
    assert k.status()["objects"] == 1


def test_no_sobrescribe_sin_permiso(tmp_path):
    k = MiniKms(tmp_path)
    k.put("a", b"1")
    with pytest.raises(KmsError):
        k.put("a", b"2")
    k.put("a", b"2", overwrite=True)
    assert k.get("a") == b"2"


def test_ids_peligrosos(tmp_path):
    k = MiniKms(tmp_path)
    for bad in ("../x", "a/b", ".oculto", "", "x" * 65):
        with pytest.raises(KmsError):
            k.put(bad, b"x")


def test_rotacion_no_recifra_datos(tmp_path):
    k = MiniKms(tmp_path)
    k.put("a", b"hola")
    antes = sha(tmp_path / "objects" / "a.bin")
    assert k.active_version == 1
    assert k.rotate() == 2
    assert sha(tmp_path / "objects" / "a.bin") == antes
    assert json.loads((tmp_path / "objects" / "a.dek.json").read_text())["kek_version"] == 2
    assert k.get("a") == b"hola"
    assert not (tmp_path / "keks" / "v1.key").exists()


def test_persistencia_entre_instancias(tmp_path):
    MiniKms(tmp_path).put("a", b"x")
    k2 = MiniKms(tmp_path)
    assert k2.get("a") == b"x"


def test_dek_alterada_se_rechaza(tmp_path):
    k = MiniKms(tmp_path)
    k.put("a", b"x")
    p = tmp_path / "objects" / "a.dek.json"
    meta = json.loads(p.read_text())
    import base64
    raw = bytearray(base64.b64decode(meta["wrapped_dek"]))
    raw[3] ^= 1
    meta["wrapped_dek"] = base64.b64encode(bytes(raw)).decode()
    p.write_text(json.dumps(meta))
    with pytest.raises(IntegrityError):
        k.get("a")


def test_ciphertext_alterado_se_rechaza(tmp_path):
    k = MiniKms(tmp_path)
    k.put("a", b"x" * 100)
    p = tmp_path / "objects" / "a.bin"
    data = bytearray(p.read_bytes())
    data[20] ^= 1
    p.write_bytes(bytes(data))
    with pytest.raises(IntegrityError):
        k.get("a")


def test_intercambiar_objetos_se_detecta_por_aad(tmp_path):
    k = MiniKms(tmp_path)
    k.put("a", b"AAAA")
    k.put("b", b"BBBB")
    (tmp_path / "objects" / "a.bin").write_bytes((tmp_path / "objects" / "b.bin").read_bytes())
    (tmp_path / "objects" / "a.dek.json").write_bytes((tmp_path / "objects" / "b.dek.json").read_bytes())
    with pytest.raises(IntegrityError):
        k.get("a")


def test_kek_corrupta_detectada_por_kcv(tmp_path):
    k = MiniKms(tmp_path)
    k.put("a", b"x")
    (tmp_path / "keks" / "v1.key").write_bytes(os.urandom(32))
    with pytest.raises(KmsError):
        k.get("a")


def test_permisos(tmp_path):
    k = MiniKms(tmp_path)
    k.put("a", b"x")
    mode = stat.S_IMODE((tmp_path / "keks" / "v1.key").stat().st_mode)
    if os.name == "posix":
        assert mode == 0o600
        assert stat.S_IMODE(tmp_path.stat().st_mode) in (0o700, 0o755, 0o775)
    else:
        assert mode & (stat.S_IRUSR | stat.S_IWUSR)
