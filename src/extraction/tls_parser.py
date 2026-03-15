
"""TLS handshake metadata extraction utilities for observable plaintext fields."""

from __future__ import annotations

import logging
from typing import Any


class TLSParser:
    """Extract TLS ClientHello and ServerHello handshake metadata from raw packets."""

    def __init__(self) -> None:
        """Initialize TLS parser logger."""
        self._logger = logging.getLogger(__name__)

    def extract_client_hello(self, raw_packet: object) -> dict[str, Any] | None:
        """Extract observable ClientHello fields, returning None when packet is not ClientHello."""
        if not self.is_client_hello(raw_packet):
            return None

        result: dict[str, Any] = {}
        tls_layer = self._get_tls_layer(raw_packet)
        if tls_layer is None:
            return None

        value = self._safe_getattr(tls_layer, "handshake_version", "tls_version")
        version = self._to_int_hex(value)
        if version is not None:
            result["tls_version"] = version

        value = self._safe_getattr(tls_layer, "handshake_ciphersuite", "cipher_suites")
        cipher_suites = self._to_int_list_hex(value)
        if cipher_suites:
            result["cipher_suites"] = cipher_suites

        value = self._safe_getattr(tls_layer, "handshake_extension_type", "extensions")
        extensions = self._to_int_list_hex(value)
        if extensions:
            result["extensions"] = extensions

        value = self._safe_getattr(
            tls_layer, "handshake_extensions_supported_group", "elliptic_curves"
        )
        elliptic_curves = self._to_int_list_hex(value)
        if elliptic_curves:
            result["elliptic_curves"] = elliptic_curves

        value = self._safe_getattr(
            tls_layer, "handshake_extensions_ec_point_format", "ec_point_formats"
        )
        ec_point_formats = self._to_int_list_hex(value)
        if ec_point_formats:
            result["ec_point_formats"] = ec_point_formats

        sni = self._safe_getattr(tls_layer, "handshake_extensions_server_name", "sni")
        if isinstance(sni, str) and sni.strip():
            result["sni"] = sni.strip()
        elif sni is not None:
            result["sni"] = str(sni)

        alpn = self._safe_getattr(tls_layer, "handshake_extensions_alpn_str", "alpn")
        if isinstance(alpn, str) and alpn.strip():
            result["alpn"] = alpn.strip()
        elif alpn is not None:
            result["alpn"] = str(alpn)

        return result

    def extract_server_hello(self, raw_packet: object) -> dict[str, Any] | None:
        """Extract observable ServerHello fields, returning None when packet is not ServerHello."""
        if not self._has_handshake_type(raw_packet, "2"):
            return None

        tls_layer = self._get_tls_layer(raw_packet)
        if tls_layer is None:
            return None

        result: dict[str, Any] = {}

        value = self._safe_getattr(tls_layer, "handshake_version", "tls_version")
        tls_version = self._to_int(value)
        if tls_version is not None:
            result["tls_version"] = tls_version

        value = self._safe_getattr(tls_layer, "handshake_ciphersuite", "selected_cipher")
        selected_cipher = self._to_int(value)
        if selected_cipher is not None:
            result["selected_cipher"] = selected_cipher

        session_id = self._safe_getattr(tls_layer, "handshake_session_id", "session_id")
        if isinstance(session_id, str) and session_id.strip():
            result["session_id"] = session_id.strip()
        elif session_id is not None:
            result["session_id"] = str(session_id)

        return result

    def is_client_hello(self, raw_packet: object) -> bool:
        """Return True when packet has TLS layer and ClientHello handshake type."""
        return self._has_handshake_type(raw_packet, "1")

    def is_certificate_packet(self, raw_packet: object) -> bool:
        """Return True when packet has TLS certificate handshake message type."""
        try:
            if self._has_handshake_type(raw_packet, "11"):
                return True
            tls_layer = self._get_tls_layer(raw_packet)
            if tls_layer is None:
                return False
            return hasattr(tls_layer, "x509af_subject")
        except Exception:
            return False

    def _has_handshake_type(self, raw_packet: object, expected: str) -> bool:
        try:
            tls_layer = self._get_tls_layer(raw_packet)
            if tls_layer is None:
                return False
            handshake_type = getattr(tls_layer, "handshake_type", None)
            if handshake_type is None:
                return False
            values = [item.strip() for item in str(handshake_type).split(",")]
            return expected in values
        except Exception:
            return False

    def _get_tls_layer(self, raw_packet: object) -> Any | None:
        try:
            if hasattr(raw_packet, "tls"):
                return getattr(raw_packet, "tls")
            if hasattr(raw_packet, "ssl"):
                return getattr(raw_packet, "ssl")
            return None
        except Exception:
            return None

    def _safe_getattr(self, obj: object, attr_name: str, field_name: str) -> Any | None:
        try:
            value = getattr(obj, attr_name)
            if value is None:
                self._logger.debug("TLS field missing: %s", field_name)
                return None
            return value
        except Exception as exc:
            self._logger.debug("TLS field missing: %s (%s)", field_name, exc)
            return None

    def _to_int(self, value: Any) -> int | None:
        try:
            if value is None:
                return None
            return int(str(value).strip(), 0)
        except Exception as exc:
            self._logger.debug("Failed to convert value to int: %s", exc)
            return None

    def _to_int_hex(self, value: Any) -> int | None:
        try:
            if value is None:
                return None
            return int(str(value).strip(), 16)
        except Exception as exc:
            self._logger.debug("Failed to convert hex value to int: %s", exc)
            return None

    def _to_int_list_hex(self, value: Any) -> list[int]:
        try:
            if value is None:
                return []
            if isinstance(value, (list, tuple, set)):
                parts = [str(item).strip() for item in value if str(item).strip()]
            else:
                text = str(value).strip()
                if not text:
                    return []
                parts = [item.strip() for item in text.split(",") if item.strip()]
            parsed: list[int] = []
            for part in parts:
                try:
                    parsed.append(int(part, 16))
                except Exception as exc:
                    self._logger.debug("Skipping malformed TLS hex list value '%s': %s", part, exc)
            return parsed
        except Exception as exc:
            self._logger.debug("Failed to parse TLS hex numeric list: %s", exc)
            return []

    def _to_int_list(self, value: Any) -> list[int]:
        try:
            if value is None:
                return []
            if isinstance(value, (list, tuple, set)):
                parts = [str(item).strip() for item in value if str(item).strip()]
            else:
                text = str(value).strip()
                if not text:
                    return []
                parts = [item.strip() for item in text.split(",") if item.strip()]
            parsed: list[int] = []
            for part in parts:
                try:
                    parsed.append(int(part, 0))
                except Exception as exc:
                    self._logger.debug("Skipping malformed TLS numeric list value '%s': %s", part, exc)
            return parsed
        except Exception as exc:
            self._logger.debug("Failed to parse TLS numeric list: %s", exc)
            return []
