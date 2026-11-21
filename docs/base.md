# Etapa 1 — La Base: primitivas criptográficas y utilidades comunes

> **Alcance:** este documento describe la primera etapa del proyecto: el paquete
> [`kmssuite.common`](../src/kmssuite/common/__init__.py), la capa de "base" sobre la que
> se construyen los tres servicios del repo (Mini-KMS, Provisión de claves y Handshake
> tipo WPA2).
>
> **Documentación relacionada:** [Etapa 2 — MiniKMS](minikms.md)

---

## 1. Resumen

La **Base** es una biblioteca interna (no expuesta como API pública) que concentra:

| Área | Módulo | Propósito |
|---|---|---|
| Envoltura de claves (RFC 3394) | [`keywrap.py`](../src/kmssuite/common/keywrap.py) | `wrap_key` / `unwrap_key` con verificación de ICV |
| AEAD (AES-GCM) | [`aead.py`](../src/kmssuite/common/aead.py) | `seal` / `open_sealed` con AAD |
| Aleatoriedad | [`drbg.py`](../src/kmssuite/common/drbg.py) | HMAC_DRBG (NIST SP 800-90A) con SHA-256 |
| Derivación de claves | [`prf.py`](../src/kmssuite/common/prf.py) | PRF/KDF intercambiables (HMAC-SHA1/256, HKDF-SHA256) |
| Transporte | [`framing.py`](../src/kmssuite/common/framing.py) | Tramas TCP: longitud + JSON UTF-8, binarios en base64 |
| Servidor | [`server.py`](../src/kmssuite/common/server.py) | Servidor TCP con un hilo por conexión |
| Configuración | [`config.py`](../src/kmssuite/common/config.py) | Lectura de variables de entorno |
| Sistema de archivos | [`fsutil.py`](../src/kmssuite/common/fsutil.py) | Escritura atómica con permisos restringidos |

Todo el código depende únicamente de la librería
[`cryptography`](../pyproject.toml) (`>=42`) y de la librería estándar de Python (≥ 3.10).

**Principio de diseño:** un único tipo de excepción de integridad —
[`IntegrityError`](../src/kmssuite/common/keywrap.py:10) — definido en `keywrap` y reusado
en `aead`. Cualquier verificación criptográfica que falle (ICV, tag GCM, MIC) termina en
`IntegrityError`; **siempre se rechaza, nunca se "arregla" el dato**.

---

## 2. Envoltura de claves — `keywrap`

Implementa **AES Key Wrap** según [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394).

| Función | Descripción |
|---|---|
| [`wrap_key(kek, key)`](../src/kmssuite/common/keywrap.py:14) | Envuelve una clave con una KEK. Devuelve el bloque envolvente con ICV |
| [`unwrap_key(kek, wrapped)`](../src/kmssuite/common/keywrap.py:22) | Desenvuelve; si el ICV no verifica, lanza `IntegrityError` |
| [`IntegrityError`](../src/kmssuite/common/keywrap.py:10) | Excepción base de la suite para cualquier fallo de integridad |

**Restricciones de entrada:**

- KEK: 16, 24 o 32 bytes (AES-128/192/256).
- Clave a envolver: ≥ 16 bytes y múltiplo de 8.

Los vectores de prueba de la RFC están cubiertos por
[`test_keywrap_aead.py`](../tests/test_keywrap_aead.py) (`test_rfc3394_128bit`,
`test_rfc3394_256kek_256key`).

## 3. AEAD — `aead` (AES-GCM)

| Constante / función | Valor / descripción |
|---|---|
| [`NONCE_LEN`](../src/kmssuite/common/aead.py:10) | 12 bytes (96 bits, recomendado para GCM) |
| [`TAG_LEN`](../src/kmssuite/common/aead.py:11) | 16 bytes (128 bits) |
| [`seal(key, plaintext, aad)`](../src/kmssuite/common/aead.py:14) | Genera un nonce aleatorio (`os.urandom`) y devuelve `nonce ‖ ciphertext ‖ tag` |
| [`open_sealed(key, blob, aad)`](../src/kmssuite/common/aead.py:19) | Verifica el tag y devuelve el plaintext; `IntegrityError` si algo no cuadra |

**Detalles de seguridad:**

- El nonce **nunca** se reutiliza: se genera fresco en cada `seal`.
- El parámetro `aad` (Associated Authenticated Data) permite **vincular el cifrado a un
  contexto** — p. ej. el `obj_id` en MiniKMS — de modo que intercambiar dos objetos
  cifrados se detecta como fallo de integridad (ver
  [`test_intercambiar_objetos_se_detecta_por_aad`](../tests/test_kms_core.py:81)).
- Un `blob` más corto que `NONCE_LEN + TAG_LEN` se rechaza inmediatamente.

## 4. Aleatoriedad — `drbg`

Implementa **HMAC_DRBG** según [NIST SP 800-90A](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final)
con SHA-256, sembrado desde `os.urandom`.

| Elemento | Descripción |
|---|---|
| [`HmacDrbg`](../src/kmssuite/common/drbg.py:13) | Clase principal; seed ≥ 32 bytes (48 por defecto) |
| [`generate(n, additional)`](../src/kmssuite/common/drbg.py:43) | Devuelve `n` bytes (1…65536) |
| [`reseed(entropy, additional)`](../src/kmssuite/common/drbg.py:36) | Reinicia el estado con nueva entropía |
| [`get_drbg()`](../src/kmssuite/common/drbg.py:65) | Singleton de proceso (thread-safe) |
| [`random_bytes(n)`](../src/kmssuite/common/drbg.py:73) | Helper: `n` bytes del DRBG por defecto |

**Mecánicas internas:**

- Re-seed forzado tras `1 << 20` llamadas a `generate` (límite de reseed de 800-90A).
- Bloqueo con `threading.Lock`: el DRBG es seguro para uso multi-hilo.
- La salida es **determinista dada la misma semilla** — eso permite probarlo sin
  aleatoriedad real (ver [`test_drbg.py`](../tests/test_drbg.py)).

## 5. Derivación de claves — `prf`

Firma común para todos los PRF/KDF:

```python
derive(name, key, label, context, length) -> bytes
```

| Nombre | Construcción |
|---|---|
| `"hmac-sha1"` | PRF por contador: `HMAC(key, label ‖ 0x00 ‖ context ‖ i)` encadenada |
| `"hmac-sha256"` | Ídem con SHA-256 |
| `"hkdf-sha256"` | [HKDF](https://www.rfc-editor.org/rfc/rfc5869) con salt=`label`, info=`context` |

El registro está en [`PRFS`](../src/kmssuite/common/prf.py:35) y el punto de entrada es
[`derive()`](../src/kmssuite/common/prf.py:42). PRF desconocida o longitud fuera de rango
(> 255 bloques) ⇒ `ValueError`.

**Conexión con 802.11i:** la forma del PRF por contador coincide con la expansión de
claves de IEEE 802.11i (p. ej. `PTK = PRF-512(PMK, "Pairwise key expansion", min(MAC_A,MAC_B)‖max(...))`),
por lo que este módulo sirve directamente para la etapa de Handshake tipo WPA2.
Los tests incluyen el vector PMK estándar de 802.11i
([`test_pmk_vector_ieee_80211i`](../tests/test_prf.py:19)) y el caso 1 de HKDF/RFC 5869
([`test_hkdf_rfc5869_caso1`](../tests/test_prf.py:8)).

## 6. Transporte — `framing`

Formato de trama para todos los servicios TCP del repo:

```
┌──────────────────────────┬─────────────────────────────┐
│ 4 bytes: longitud (BE)   │ JSON UTF-8 de esa longitud  │
└──────────────────────────┴─────────────────────────────┘
```

- Los valores binarios viajan **en base64** dentro del JSON
  (helpers [`b64e`](../src/kmssuite/common/framing.py:12) / [`b64d`](../src/kmssuite/common/framing.py:16)).
- Límite duro: [`MAX_FRAME`](../src/kmssuite/common/framing.py:9) = 64 MiB.
- [`send_msg(sock, obj)`](../src/kmssuite/common/framing.py:20) — serializa y envía con `sendall`.
- [`recv_msg(sock)`](../src/kmssuite/common/framing.py:37) — lee longitud, valida el
  límite, descodifica y exige que el resultado sea un `dict`.
- [`recv_exact(sock, n)`](../src/kmssuite/common/framing.py:27) — lectura completa con
  `ConnectionError` si el otro extremo cierra.

## 7. Servidor — `server`

[`make_server(host, port, handle, timeout)`](../src/kmssuite/common/server.py:11)
construye un `socketserver.ThreadingTCPServer` con:

- **Un hilo por conexión** (`daemon_threads = True`).
- `allow_reuse_address = True` (permite reinicios rápidos en desarrollo).
- Timeout por socket (30 s por defecto).
- Manejo centralizado de errores: `ConnectionError`, `TimeoutError`, `ValueError` y
  `KeyError` se registran como *warning* (comportamiento esperado); cualquier otra
  excepción se registra con *traceback* completo.

El parámetro `handle(sock, addr)` contiene la lógica concreta del servicio — es la
"inyección" por la que `kms/server.py` (y luego `prov` y `wpa`) reutilizan este
mecanismo. [`serve_forever`](../src/kmssuite/common/server.py:29) es el atajo
blockeante para ejecutar un servicio.

## 8. Configuración — `config`

- [`env(name, default, required)`](../src/kmssuite/common/config.py:7) — lee una variable
  de entorno; `required=True` lanza `RuntimeError` si falta o está vacía.
- [`env_int(name, default)`](../src/kmssuite/common/config.py:14) — variante numérica.

Los ejemplos de variables se encuentran en
[`config/secrets.example.env`](../config/secrets.example.env) y
[`config/hosts.example.env`](../config/hosts.example.env).

## 9. Sistema de archivos — `fsutil`

[`atomic_write(path, data, mode=0o600)`](../src/kmssuite/common/fsutil.py:9) garantiza
**escrituras atómicas** (crítico para no corromper KEKs ni objetos en medio de una
rotación):

1. Crea un temporal `.tmp-…` **en el mismo directorio** (mismo volumen → `rename` atómico).
2. `fchmod` a `0o600` **antes** de escribir el contenido.
3. `fsync` del descriptor.
4. `os.replace(tmp, path)`.
5. Ante cualquier excepción, elimina el temporal.

## 10. Tests de la Base

| Archivo | Qué cubre |
|---|---|
| [`tests/test_keywrap_aead.py`](../tests/test_keywrap_aead.py) | Vectores RFC 3394, detección de alteraciones, AAD de GCM, nonces distintos |
| [`tests/test_drbg.py`](../tests/test_drbg.py) | Determinismo, reseed, longitudes, distribución de bits, singleton |
| [`tests/test_prf.py`](../tests/test_prf.py) | Vectores HKDF/RFC 5869, PMK 802.11i, propiedades de PRF (longitud, invarianza, sensibilidad a label/context) |
| [`tests/test_framing_server.py`](../tests/test_framing_server.py) | `atomic_write`, roundtrip de tramas, errores de trama/cierre, servidor eco |

Ejecución: `make test` (o `pytest` desde la raíz; `pyproject.toml` fija `testpaths` y `pythonpath=["src"]`).

## 11. Convenciones transversales

- **Idioma de mensajes:** los mensajes de error y logs del proyecto están en español.
- **Integridad:** toda verificación criptográfica fallida ⇒ `IntegrityError`; los
  servicios de red la mapean a la respuesta genérica `{"ok": false, "error": "integridad"}`
  para **no filtrar detalles** (ver
  [`test_integridad_no_filtra_detalles`](../tests/test_kms_service.py:51)).
- **Sin estado en red:** las primitivas son puras o con estado explícito (DRBG); el
  estado persistente vive en disco y se protege con `atomic_write`.
- **Un solo tipo de excepción de integridad** para que los servicios no tengan que
  distinguir entre "ICV malo" y "tag malo".

## 12. Cómo se usa la Base en el resto del repo

```
kmssuite.common
   ├── keywrap ──┐
   ├── aead ─────┤  ┌──────────────┐
   ├── drbg ─────┼─▶│ kms/core.py  │  ← MiniKMS (etapa 2, ver docs/minikms.md)
   ├── prf ──────┤  └──────────────┘
   ├── framing ──┤  ┌──────────────┐
   ├── server ───┼─▶│ kms/server   │
   ├── config ───┤  │ kms/client   │
   └── fsutil ───┘  └──────────────┘
        (también lo usarán prov/ y wpa/ en las etapas siguientes)
```

La Base **no** conoce a MiniKMS: la dependencia va en una sola dirección, lo que permite
testear cada primitiva de forma aislada y reutilizarlas en `prov` (Provisión de claves) y
`wpa` (Handshake tipo WPA2) sin cambios.
