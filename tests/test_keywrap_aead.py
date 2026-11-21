import pytest
from kmssuite.common.aead import open_sealed, seal
from kmssuite.common.keywrap import IntegrityError, unwrap_key, wrap_key


def test_rfc3394_128bit():  # RFC 3394 §4.1
    kek = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    exp = bytes.fromhex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    assert wrap_key(kek, key) == exp
    assert unwrap_key(kek, exp) == key


def test_rfc3394_256kek_256key():  # RFC 3394 §4.6
    kek = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    key = bytes.fromhex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
    exp = bytes.fromhex(
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    )
    assert wrap_key(kek, key) == exp
    assert unwrap_key(kek, exp) == key


def test_unwrap_detecta_alteracion():
    kek, key = bytes(32), bytes(range(32))
    w = bytearray(wrap_key(kek, key))
    w[5] ^= 0x01
    with pytest.raises(IntegrityError):
        unwrap_key(kek, bytes(w))


def test_unwrap_kek_incorrecta_y_longitud_mala():
    w = wrap_key(bytes(32), bytes(range(32)))
    with pytest.raises(IntegrityError):
        unwrap_key(b"\x01" * 32, w)
    with pytest.raises(IntegrityError):
        unwrap_key(bytes(32), b"corto")


def test_argumentos_invalidos():
    with pytest.raises(ValueError):
        wrap_key(b"x" * 10, bytes(32))
    with pytest.raises(ValueError):
        wrap_key(bytes(32), bytes(15))


def test_gcm_roundtrip_y_aad():
    k = bytes(32)
    blob = seal(k, b"hola", aad=b"id1")
    assert open_sealed(k, blob, aad=b"id1") == b"hola"
    with pytest.raises(IntegrityError):
        open_sealed(k, blob, aad=b"id2")


def test_gcm_alteracion_y_nonces_distintos():
    k = bytes(32)
    b1, b2 = seal(k, b"x"), seal(k, b"x")
    assert b1 != b2
    t = bytearray(b1)
    t[-1] ^= 1
    with pytest.raises(IntegrityError):
        open_sealed(k, bytes(t))
    with pytest.raises(IntegrityError):
        open_sealed(k, b"\x00" * 5)
