import hashlib
import hmac

import pytest
from kmssuite.common.prf import PRFS, derive


def test_hkdf_rfc5869_caso1():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    exp = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert derive("hkdf-sha256", ikm, salt, info, 42) == exp


def test_pmk_vector_ieee_80211i():
    pmk = hashlib.pbkdf2_hmac("sha1", b"password", b"IEEE", 4096, 32)
    assert pmk.hex() == "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"


def test_hmac_sha1_construccion_80211i_manual():
    key, label, ctx = b"k" * 32, b"Pairwise key expansion", b"c" * 76
    raw = b"".join(hmac.new(key, label + b"\x00" + ctx + bytes([i]), hashlib.sha1).digest() for i in range(3))
    assert derive("hmac-sha1", key, label, ctx, 48) == raw[:48]


@pytest.mark.parametrize("name", sorted(PRFS))
def test_propiedades_generales(name):
    a = derive(name, b"k" * 32, b"lab", b"ctx", 48)
    assert len(a) == 48
    assert a == derive(name, b"k" * 32, b"lab", b"ctx", 48)
    assert a != derive(name, b"j" * 32, b"lab", b"ctx", 48)
    assert a != derive(name, b"k" * 32, b"lab2", b"ctx", 48)
    assert a != derive(name, b"k" * 32, b"lab", b"ctx2", 48)
    assert derive(name, b"k" * 32, b"lab", b"ctx", 16) == a[:16]


def test_errores():
    with pytest.raises(ValueError):
        derive("md5", b"k", b"l", b"c", 16)
    with pytest.raises(ValueError):
        derive("hmac-sha256", b"k", b"l", b"c", 0)
