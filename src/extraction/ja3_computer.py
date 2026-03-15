
"""JA3 fingerprint computation from observable TLS ClientHello metadata."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from src.extraction.tls_parser import TLSParser

GREASE_VALUES: set[int] = {
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
}


class JA3Computer:
    """Compute JA3 string and MD5 fingerprint hashes for TLS ClientHello packets."""

    def __init__(self) -> None:
        """Initialize JA3 computer logger."""
        self._logger = logging.getLogger(__name__)

    def compute(self, client_hello: dict[str, Any] | None) -> str | None:
        """Compute JA3 MD5 hash from parsed ClientHello fields."""
        if client_hello is None:
            return None

        version_raw = client_hello.get("tls_version")
        if version_raw is None:
            return None

        try:
            version = int(version_raw)
            ciphers = self._filter_grease(self._to_int_list(client_hello.get("cipher_suites")))
            extensions = self._filter_grease(self._to_int_list(client_hello.get("extensions")))
            curves = self._filter_grease(self._to_int_list(client_hello.get("elliptic_curves")))
            ec_formats = self._to_int_list(client_hello.get("ec_point_formats"))

            ja3_string = self._build_ja3_string(version, ciphers, extensions, curves, ec_formats)
            self._logger.debug("JA3 string: %s", ja3_string)
            ja3_hash = hashlib.md5(ja3_string.encode("utf-8")).hexdigest()
            self._logger.debug("JA3 hash: %s", ja3_hash)
            return ja3_hash
        except Exception as exc:
            self._logger.debug("Failed to compute JA3 hash: %s", exc)
            return None

    def compute_from_raw(self, raw_packet: object) -> str | None:
        """Extract ClientHello from a raw packet and compute JA3 hash."""
        precomputed = self.read_precomputed(raw_packet)
        if precomputed is not None:
            self._logger.debug("JA3 method used: precomputed")
            return precomputed

        self._logger.debug("JA3 method used: manual")
        parser = TLSParser()
        client_hello = parser.extract_client_hello(raw_packet)
        return self.compute(client_hello)

    def read_precomputed(self, raw_packet: object) -> str | None:
        """Read precomputed JA3 hash from TShark/PyShark when available."""
        try:
            if not hasattr(raw_packet, "tls"):
                return None
            tls_layer = getattr(raw_packet, "tls")
            value = getattr(tls_layer, "handshake_ja3", None)
            if value is None:
                return None
            ja3 = str(value).strip()
            return ja3 or None
        except Exception as exc:
            self._logger.debug("Precomputed JA3 not available: %s", exc)
            return None

    def _filter_grease(self, values: list[int]) -> list[int]:
        """Remove GREASE values from a TLS numeric list."""
        return [value for value in values if value not in GREASE_VALUES]

    def _build_ja3_string(
        self,
        version: int,
        ciphers: list[int],
        extensions: list[int],
        curves: list[int],
        ec_formats: list[int],
    ) -> str:
        """Build the JA3 pre-hash canonical string."""
        ciphers_text = "-".join(str(value) for value in ciphers)
        extensions_text = "-".join(str(value) for value in extensions)
        curves_text = "-".join(str(value) for value in curves)
        ec_formats_text = "-".join(str(value) for value in ec_formats)
        return f"{version},{ciphers_text},{extensions_text},{curves_text},{ec_formats_text}"

    def _to_int_list(self, value: Any) -> list[int]:
        try:
            if value is None:
                return []
            if isinstance(value, (list, tuple, set)):
                raw_parts = [str(item).strip() for item in value if str(item).strip()]
            else:
                text = str(value).strip()
                if not text:
                    return []
                raw_parts = [item.strip() for item in text.split(",") if item.strip()]

            parsed: list[int] = []
            for part in raw_parts:
                try:
                    parsed.append(int(part, 0))
                except Exception as exc:
                    self._logger.debug("Skipping malformed JA3 numeric value '%s': %s", part, exc)
            return parsed
        except Exception as exc:
            self._logger.debug("Failed parsing JA3 numeric list: %s", exc)
            return []
