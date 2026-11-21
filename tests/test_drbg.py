import pytest
from kmssuite.common.drbg import HmacDrbg, get_drbg, random_bytes

SEED = bytes(range(48))


def test_determinista_con_misma_semilla():
    assert HmacDrbg(SEED).generate(64) == HmacDrbg(SEED).generate(64)


def test_semillas_distintas_dan_salidas_distintas():
    assert HmacDrbg(SEED).generate(32) != HmacDrbg(bytes(48)).generate(32)


def test_llamadas_sucesivas_difieren():
    d = HmacDrbg(SEED)
    assert d.generate(32) != d.generate(32)


def test_longitudes():
    d = HmacDrbg()
    for n in (1, 16, 31, 32, 33, 100, 1000):
        assert len(d.generate(n)) == n


def test_reseed_cambia_salida():
    a, b = HmacDrbg(SEED), HmacDrbg(SEED)
    b.reseed(b"x" * 32)
    assert a.generate(32) != b.generate(32)


def test_additional_input_cambia_salida():
    assert HmacDrbg(SEED).generate(32) != HmacDrbg(SEED).generate(32, additional=b"a")


def test_errores():
    with pytest.raises(ValueError):
        HmacDrbg(b"corta")
    with pytest.raises(ValueError):
        HmacDrbg().generate(0)


def test_monobit_aproximado():
    data = HmacDrbg().generate(10000)
    ones = sum(bin(x).count("1") for x in data)
    assert 0.48 < ones / (len(data) * 8) < 0.52


def test_singleton_y_helper():
    assert get_drbg() is get_drbg()
    assert len(random_bytes(16)) == 16
