# KMS_KeyWrapping_2026_I

Suite de seguridad criptográfica y distribución de claves, dividida en tres servicios:
**Mini-KMS**, **Provisión de claves** y **Handshake tipo WPA2** con PRF.

## Documentación por etapas

| Etapa | Estado | Documentación |
|---|---|---|
| **1. La Base** — primitivas criptográficas y utilidades comunes (`kmssuite.common`: RFC 3394, AES-GCM, HMAC_DRBG, PRF/KDF, framing TCP, servidor, config, escritura atómica) | completada | [docs/base.md](docs/base.md) |
| **2. MiniKMS** — cifrado por sobres con rotación de KEK, servicio TCP y CLI (`kmssuite.kms`) | completada | [docs/minikms.md](docs/minikms.md) |
| **3. Provisión de claves + Handshake tipo WPA2** (`kmssuite.prov`, `kmssuite.wpa`) | en curso | — |

## Estructura

```
src/kmssuite/
├── common/   # Etapa 1: la Base (keywrap, aead, drbg, prf, framing, server, config, fsutil)
├── kms/      # Etapa 2: MiniKMS (core, server, client, cli)
├── prov/     # Etapa 3: provisión de claves (pendiente)
├── wpa/      # Etapa 3: handshake tipo WPA2 (pendiente)
└── bench/    # Banco de pruebas para medir y elegir la PRF
tests/        # pytest (make test)
config/       # plantillas de entorno (secrets, hosts)
deploy/       # despliegue systemd
```

## Comandos rápidos

```bash
make venv     # crea .venv e instala el paquete en modo editable
make test     # ejecuta pytest
make bench    # benchmarks de PRF → bench/results
make report   # genera el reporte de benchmarks
```
