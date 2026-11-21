"""CLI: python -m kmssuite.kms.cli {put NAME FILE | get NAME OUT | rotate | list | status}"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from kmssuite.kms.client import KmsClient, KmsRemoteError


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kms")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("put"); p.add_argument("name"); p.add_argument("file"); p.add_argument("--overwrite", action="store_true")
    g = sub.add_parser("get"); g.add_argument("name"); g.add_argument("out")
    sub.add_parser("rotate"); sub.add_parser("list"); sub.add_parser("status")
    args = ap.parse_args(argv)
    client = KmsClient.from_env()
    try:
        if args.cmd == "put":
            client.put(args.name, Path(args.file).read_bytes(), overwrite=args.overwrite)
            print(f"cifrado y guardado: {args.name}")
        elif args.cmd == "get":
            Path(args.out).write_bytes(client.get(args.name))
            print(f"descifrado en: {args.out}")
        elif args.cmd == "rotate":
            print(f"KEK rotada; versión activa = {client.rotate()}")
        elif args.cmd == "list":
            for o in client.list():
                print(f"{o['id']}\tkek=v{o['kek_version']}\t{o['size']} B")
        else:
            print(client.status())
    except KmsRemoteError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
