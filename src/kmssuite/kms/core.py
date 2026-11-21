"""Mini-KMS: cifrado por sobres (envelope encryption) con rotación de KEK."""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

from kmssuite.common.aead import open_sealed, seal
from kmssuite.common.drbg import HmacDrbg, get_drbg
from kmssuite.common.framing import b64d, b64e
from kmssuite.common.fsutil import atomic_write
from kmssuite.common.keywrap import IntegrityError, unwrap_key, wrap_key
from kmssuite.common.prf import derive

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class KmsError(Exception):
    """Error de uso (id inválido, objeto inexistente, ya existe...)."""


class MiniKms:
    def __init__(self, data_dir: str | Path, prf_name: str = "hmac-sha256", drbg: HmacDrbg | None = None):
        self.root = Path(data_dir)
        self.keks_dir = self.root / "keks"
        self.obj_dir = self.root / "objects"
        self.state_path = self.root / "state.json"
        for d in (self.root, self.keks_dir, self.obj_dir):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.drbg = drbg or get_drbg()
        self._lock = threading.RLock()
        if self.state_path.exists():
            self.prf_name = self._read_state()["prf"]
        else:
            self.prf_name = prf_name
            self._write_state({"active_version": 0, "prf": prf_name, "kcv": {}})
            self._create_kek(1)

    # ---------- estado y KEK ----------
    def _read_state(self) -> dict:
        return json.loads(self.state_path.read_text())

    def _write_state(self, state: dict) -> None:
        atomic_write(self.state_path, json.dumps(state).encode())

    def _kcv(self, kek: bytes) -> str:
        return derive(self.prf_name, kek, b"minikms-kcv", b"", 4).hex()

    def _create_kek(self, version: int) -> None:
        kek = self.drbg.generate(32)
        atomic_write(self.keks_dir / f"v{version}.key", kek)
        state = self._read_state()
        state["kcv"][str(version)] = self._kcv(kek)
        state["active_version"] = version
        self._write_state(state)

    def _load_kek(self, version: int) -> bytes:
        path = self.keks_dir / f"v{version}.key"
        if not path.exists():
            raise KmsError(f"KEK v{version} no existe (¿retirada?)")
        kek = path.read_bytes()
        if self._kcv(kek) != self._read_state()["kcv"].get(str(version)):
            raise KmsError(f"KEK v{version} corrupta (KCV no coincide)")
        return kek

    @property
    def active_version(self) -> int:
        return self._read_state()["active_version"]

    # ---------- objetos ----------
    def _paths(self, obj_id: str) -> tuple[Path, Path]:
        if not _ID_RE.match(obj_id):
            raise KmsError("id inválido")
        return self.obj_dir / f"{obj_id}.bin", self.obj_dir / f"{obj_id}.dek.json"

    def put(self, obj_id: str, data: bytes, overwrite: bool = False) -> str:
        bin_path, meta_path = self._paths(obj_id)
        with self._lock:
            if meta_path.exists() and not overwrite:
                raise KmsError("el objeto ya existe")
            version = self.active_version
            dek = self.drbg.generate(32)
            atomic_write(bin_path, seal(dek, data, aad=obj_id.encode()))
            meta = {"kek_version": version, "wrapped_dek": b64e(wrap_key(self._load_kek(version), dek))}
            atomic_write(meta_path, json.dumps(meta).encode())
        return obj_id

    def get(self, obj_id: str) -> bytes:
        bin_path, meta_path = self._paths(obj_id)
        if not meta_path.exists():
            raise KmsError("objeto inexistente")
        meta = json.loads(meta_path.read_text())
        dek = unwrap_key(self._load_kek(meta["kek_version"]), b64d(meta["wrapped_dek"]))
        return open_sealed(dek, bin_path.read_bytes(), aad=obj_id.encode())

    def list_objects(self) -> list[dict]:
        out = []
        for meta_path in sorted(self.obj_dir.glob("*.dek.json")):
            obj_id = meta_path.name[: -len(".dek.json")]
            meta = json.loads(meta_path.read_text())
            out.append({"id": obj_id, "kek_version": meta["kek_version"],
                        "size": (self.obj_dir / f"{obj_id}.bin").stat().st_size})
        return out

    # ---------- rotación ----------
    def rotate(self) -> int:
        with self._lock:
            self._create_kek(self.active_version + 1)
            self.rewrap_pending()
            return self.active_version

    def rewrap_pending(self) -> int:
        """Reenvuelve DEKs con versión antigua y retira KEK sin uso. Devuelve cuántas reenvolvió."""
        with self._lock:
            active = self.active_version
            new_kek = self._load_kek(active)
            count = 0
            for meta_path in self.obj_dir.glob("*.dek.json"):
                meta = json.loads(meta_path.read_text())
                if meta["kek_version"] == active:
                    continue
                dek = unwrap_key(self._load_kek(meta["kek_version"]), b64d(meta["wrapped_dek"]))
                meta = {"kek_version": active, "wrapped_dek": b64e(wrap_key(new_kek, dek))}
                atomic_write(meta_path, json.dumps(meta).encode())
                count += 1
            for key_path in self.keks_dir.glob("v*.key"):
                if int(key_path.stem[1:]) < active:
                    key_path.unlink()
            return count

    def status(self) -> dict:
        st = self._read_state()
        return {"active_version": st["active_version"], "prf": st["prf"], "objects": len(self.list_objects())}
