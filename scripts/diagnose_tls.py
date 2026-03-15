"""Temporary TLS field diagnostics for PyShark packet layer inspection."""

from __future__ import annotations

from pathlib import Path

import pyshark


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    pcap_path = project_root / "data" / "raw" / "pcap" / "test_sample.pcap"

    capture: pyshark.FileCapture | None = None
    tls_seen = 0
    try:
        capture = pyshark.FileCapture(input_file=str(pcap_path), keep_packets=False)
        for packet in capture:
            if not hasattr(packet, "tls"):
                continue

            tls_seen += 1
            tls_layer = packet.tls
            fields = dir(tls_layer)
            print(f"\n=== TLS PACKET #{tls_seen} ===")
            print("ALL TLS FIELDS:")
            print(fields)

            print("\nFIELDS CONTAINING 'handshake':")
            for name in fields:
                lower = name.lower()
                if "handshake" in lower:
                    try:
                        print(f"{name} = {getattr(tls_layer, name)}")
                    except Exception as exc:
                        print(f"{name} = <error: {exc}>")

            print("\nFIELDS CONTAINING 'version':")
            for name in fields:
                lower = name.lower()
                if "version" in lower:
                    try:
                        print(f"{name} = {getattr(tls_layer, name)}")
                    except Exception as exc:
                        print(f"{name} = <error: {exc}>")

            print("\nFIELDS CONTAINING 'sni' OR 'server_name':")
            for name in fields:
                lower = name.lower()
                if "sni" in lower or "server_name" in lower:
                    try:
                        print(f"{name} = {getattr(tls_layer, name)}")
                    except Exception as exc:
                        print(f"{name} = <error: {exc}>")

            if tls_seen >= 3:
                break
    finally:
        if capture is not None:
            capture.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
