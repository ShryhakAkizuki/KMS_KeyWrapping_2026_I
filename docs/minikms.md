# Etapa 2 — MiniKMS: cifrado por sobres con rotación de KEK

> **Alcance:** este documento describe la segunda etapa del proyecto: el servicio
> **Mini-KMS** (`kmssuite.kms`), un KMS minimalista de cifrado por sobres
> (*envelope encryption*) con rotación de clave maestra (KEK), persistencia en disco y
> servicio TCP con CLI.
>
> **Depende de:** la [Etapa 1 — La Base](base.md) (`kmssuite.common`).
>
> **Siguiente etapa (en curso):** Provisión de claves (`kmssuite.prov`) y Handshake tipo
> WPA2 (`kmssuite.wpa`), que reutilizarán los mismos mecanismos de transporte y
> configuración.

---

## 1. Resumen

MiniKMS guarda objetos arbitrarios en disco de forma cifrada y accesible por red:

- **Cifrado por sobres:** cada objeto se cifra con una **DEK** (Data Encryption Key)
  efímera; la DEK se envuelve con la **KEK** activa (RFC 3394).
- **Rotación de KEK:** se crea una nueva KEK, se reenvuelven las DEKs con ella y se
  **retira la KEK vieja** — sin recifrar los datos en disco.
- **Integridad en tres capas:** ICV del wrap (RFC 3394), tag AES-GCM del dato y
  **AAD = `obj_id`** (impide intercambiar objetos), más KCV de cada KEK.
- **Superficie pequeña:** 5 operaciones (`put`, `get`, `rotate`, `list`, `status`) por
  TCP con token de autenticación.

## 2. Arquitectura y layout en disco

```
KMS_DATA_DIR/                    (0o700)
├── state.json                   # {"active_version", "prf", "kcv": {v: hex}}
├── keks/
│   └── v{n}.key                 # KEK de n bytes=32, permisos 0o600
└── objects/
    ├── {id}.bin                 # nonce ‖ AESGCM(DEK, data, aad=id) ‖ tag
    └── {id}.dek.json            # {"kek_version": n, "wrapped_dek": b64}
```

Clases y módulos:

| Módulo | Contenido |
|---|---|
| [`kms/core.py`](../src/kmssuite/kms/core.py) | [`MiniKms`](../src/kmssuite/kms/core.py:23) — lógica local (disco) + [`KmsError`](../src/kmssuite/kms/core.py:19) |
| [`kms/server.py`](../src/kmssuite/kms/server.py) | Servicio TCP: [`make_handler`](../src/kmssuite/kms/server.py:16) y [`main`](../src/kmssuite/kms/server.py:49) |
| [`kms/client.py`](../src/kmssuite/kms/client.py) | [`KmsClient`](../src/kmssuite/kms/client.py:14) — cliente por red + [`KmsRemoteError`](../src/kmssuite/kms/client.py:10) |
| [`kms/cli.py`](../src/kmssuite/kms/cli.py) | CLI `python -m kmssuite.kms.cli` |

### 2.1 Estado (`state.json`)

Escribido solo con [`atomic_write`](../src/kmssuite/common/fsutil.py:9). Contiene:

- `active_version`: versión de la KEK vigente.
- `prf`: nombre de la PRF fijada **al crear** el almacén (no cambia después).
- `kcv`: mapa `{versión: KCV}` donde KCV =
  `PRF(kek, label="minikms-kcv", ctx="", 4 bytes).hex()`
  ([`_kcv`](../src/kmssuite/kms/core.py:47)) — huella de integridad de cada KEK.

### 2.2 Flujo `put` ([`MiniKms.put`](../src/kmssuite/kms/core.py:77))

```
put(obj_id, data, overwrite=False)
  1. validar obj_id contra  ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$   (_ID_RE)
  2. si ya existe y no overwrite  → KmsError
  3. version = active_version
  4. dek  = drbg.generate(32)                       # DEK efímera
  5. {id}.bin      = seal(dek, data, aad=obj_id)    # AES-GCM
  6. {id}.dek.json = {kek_version, wrapped_dek = wrap_key(KEK[version], dek)}
```

### 2.3 Flujo `get` ([`MiniKms.get`](../src/kmssuite/kms/core.py:89))

```
get(obj_id)
  1. leer meta → versión de KEK que envolvió la DEK
  2. kek  = _load_kek(version)        # valida KCV contra state.json
  3. dek  = unwrap_key(kek, wrapped_dek)      # falla → IntegrityError (ICV)
  4. data = open_sealed(dek, bin, aad=obj_id) # falla → IntegrityError (tag GCM)
```

Nota: `get` funciona con **cualquier versión de KEK que siga en disco**; solo la
KEK activa se usa para `put` nuevos.

## 3. Rotación de KEK

### 3.1 [`rotate()`](../src/kmssuite/kms/core.py:107)

1. Crea `v{active+1}.key` (32 bytes del DRBG) con `0o600` y registra su KCV.
2. Marca `active_version = active+1` en `state.json`.
3. Llama a `rewrap_pending()`.

### 3.2 [`rewrap_pending()`](../src/kmssuite/kms/core.py:113)

- Para cada objeto cuya `kek_version` ≠ activa: **desenvuelve** la DEK con su KEK
  antigua y la **reenvuelve** con la KEK activa. El archivo `.bin` **no se toca**
  (no se recifran los datos: solo cambia el sobre).
- Elimina de `keks/` todas las versiones `< active` (retiro de claves).
- Devuelve el número de objetos reenvueltos.

Consecuencia verificada por
[`test_rotacion_no_recifra_datos`](../tests/test_kms_core.py:38): tras `rotate()`, el
hash SHA-256 de `{id}.bin` no cambia, la meta pasa a la versión 2 y `v1.key` ya no
existe.

## 4. Garantías de integridad

| Capa | Mecanismo | Qué detecta | Test |
|---|---|---|---|
| Wrap de la DEK | ICV de RFC 3394 | DEK alterada en disco, KEK equivocada | [`test_dek_alterada_se_rechaza`](../tests/test_kms_core.py:56) |
| Dato cifrado | Tag AES-GCM | Objeto `.bin` alterado | [`test_ciphertext_alterado_se_rechaja`](../tests/test_kms_core.py:70) |
| Contexto | AAD = `obj_id` | Intercambio de objetos a↔b | [`test_intercambiar_objetos_se_detecta_por_aad`](../tests/test_kms_core.py:81) |
| KEK en disco | KCV en `state.json` | KEK corrompida/sustituida | [`test_kek_corrupta_detectada_por_kcv`](../tests/test_kms_core.py:91) |
| Red | Respuesta genérica `"integridad"` | No filtra detalles internos al cliente | [`test_integridad_no_filtra_detalles`](../tests/test_kms_service.py:51) |

Todas terminan en [`IntegrityError`](../src/kmssuite/common/keywrap.py:10) (Base, etapa 1)
o `KmsError` para el caso KCV.

## 5. Servicio TCP

### 5.1 Protocolo

Tramas de la Base (4 bytes longitud BE + JSON; binarios en base64). El cliente abre una
conexión nueva por operación; el token viaja en **cada** petición y se compara con
`hmac.compare_digest` (tiempo constante) en
[`make_handler`](../src/kmssuite/kms/server.py:16).

| Operación | Petición | Respuesta `ok=true` |
|---|---|---|
| `put` | `id`, `data` (b64), `overwrite?` | `id` |
| `get` | `id` | `data` (b64) |
| `rotate` | — | `active_version` |
| `list` | — | `objects: [{id, kek_version, size}]` |
| `status` | — | `active_version`, `prf`, `objects` |

Errores: `{"ok": false, "error": "…"}` con mensajes cortos:
`no autorizado`, `integridad`, `petición inválida` (KeyError/ValueError),
`operación desconocida`, o el texto de `KmsError` (id inválido, inexistente, ya existe…).

### 5.2 Variables de entorno

| Variable | Por defecto | Descripción |
|---|---|---|
| `KMS_DATA_DIR` | — (**obligatoria**) | Directorio del almacén (se crea si no existe) |
| `KMS_TOKEN` | — (**obligatoria**) | Token compartido del servicio |
| `KMS_PORT` | `9001` | Puerto TCP |
| `KMS_BIND` | `0.0.0.0` | Interfaz de escucha |
| `PRF_NAME` | `hmac-sha256` | PRF del KCV (solo al crear el almacén) |
| `LOG_LEVEL` | `INFO` | Nivel de logging |

Lado cliente: `KMS_HOST` (127.0.0.1), `KMS_PORT` (9001), `KMS_TOKEN` (obligatoria) —
ver [`KmsClient.from_env`](../src/kmssuite/kms/client.py:18) y
[`config/secrets.example.env`](../config/secrets.example.env).

### 5.3 Arranque

```bash
# servidor
KMS_DATA_DIR=/var/lib/minikms KMS_TOKEN="..." python -m kmssuite.kms.server

# cliente / CLI
export KMS_HOST=192.168.1.11 KMS_PORT=9001 KMS_TOKEN="..."
python -m kmssuite.kms.cli put mi-dato archivo.bin
python -m kmssuite.kms.cli get mi-dato /tmp/salida.bin
python -m kmssuite.kms.cli list
python -m kmssuite.kms.cli rotate
python -m kmssuite.kms.cli status
```

La CLI (`[main](../src/kmssuite/kms/cli.py:11)`) sale con código 0 en éxito y 2 en
`KmsRemoteError`.

## 6. Modelo de amenazas y decisiones de diseño

- **Token compartido de un solo valor:** suficiente para un laboratorio con 3 máquinas;
  no hay por diseño multiusuario ni TLS (las variables `config/hosts.example.env`
  asumen red local).
- **`0.0.0.0` por defecto:** intencional para el despliegue multi-máquina; en
  desarrollo conviene `KMS_BIND=127.0.0.1`.
- **Retiro de KEK tras rewrap:** la ventana de exposición de la KEK vieja es nula una
  vez termina `rewrap_pending` (se ejecuta dentro de `rotate` bajo el mismo lock).
- **Ids restringidos:** la regex `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` evita traversal
  (`../x`), separadores (`a/b`) y nombres vacíos/ocultos — ver
  [`test_ids_peligrosos`](../tests/test_kms_core.py:31).
- **Permiso `0o600`** en KEKs, objetos y `state.json`; `0o700` en los directorios
  (ver [`test_permisos`](../tests/test_kms_core.py:99)).
- **Persistencia entre reinicios:** todo el estado vive en disco; reabrir
  `MiniKms(dir)` recupera KEK activa, PRF y objetos
  ([`test_persistencia_entre_instancias`](../tests/test_kms_core.py:50)).

## 7. Tests de MiniKMS

| Archivo | Cobertura |
|---|---|
| [`tests/test_kms_core.py`](../tests/test_kms_core.py) | Roundtrip, overwrite, ids, rotación sin recifrar, persistencia, 5 capas de integridad, permisos |
| [`tests/test_kms_service.py`](../tests/test_kms_service.py) | CRUD por red, rotación por red, token incorrecto, errores de uso, opacidad de integridad |

Ejecución: `make test`.
