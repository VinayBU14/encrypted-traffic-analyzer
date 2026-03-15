
"""TLS metadata assembly for creating unified TLS session records per flow."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from src.extraction.certificate_parser import CertificateParser
from src.extraction.ja3_computer import JA3Computer
from src.extraction.tls_parser import TLSParser
from src.storage.models import FlowRecord, TLSSessionRecord


class MetadataAssembler:
    """Coordinate TLS extraction components to build a single TLSSessionRecord per flow."""

    def __init__(self) -> None:
        """Initialize parser/computer dependencies and logger."""
        self._tls_parser = TLSParser()
        self._ja3_computer = JA3Computer()
        self._certificate_parser = CertificateParser()
        self._logger = logging.getLogger(__name__)

    def assemble(self, flow_id: str, packets: list[dict[str, Any]]) -> TLSSessionRecord | None:
        """Assemble TLS session metadata from all packets for one flow."""
        client_hello: dict[str, Any] | None = None
        server_hello: dict[str, Any] | None = None
        cert_result: dict[str, Any] | None = None
        ja3_hash: str | None = None

        for packet in packets:
            try:
                if not bool(packet.get("has_tls_layer")):
                    continue
                raw_packet = packet.get("raw_packet")
                if raw_packet is None:
                    continue
                if self._tls_parser.is_client_hello(raw_packet):
                    client_hello = self._tls_parser.extract_client_hello(raw_packet)
                    ja3_hash = self._ja3_computer.compute_from_raw(raw_packet)
                    if ja3_hash is None:
                        ja3_hash = self._ja3_computer.compute(client_hello)
                    break
            except Exception as exc:
                self._logger.debug("ClientHello scan error for flow %s: %s", flow_id, exc)

        if client_hello is None:
            for packet in packets:
                try:
                    if not bool(packet.get("has_tls_layer")):
                        continue
                    raw_packet = packet.get("raw_packet")
                    if raw_packet is None:
                        continue
                    extracted = self._tls_parser.extract_server_hello(raw_packet)
                    if extracted is not None:
                        server_hello = extracted
                        break
                except Exception as exc:
                    self._logger.debug("ServerHello scan error for flow %s: %s", flow_id, exc)

        for packet in packets:
            try:
                if not bool(packet.get("has_tls_layer")):
                    continue
                raw_packet = packet.get("raw_packet")
                if raw_packet is None:
                    continue
                tls_layer = getattr(raw_packet, "tls", None)
                has_x509_subject = bool(tls_layer is not None and hasattr(tls_layer, "x509af_subject"))
                if self._tls_parser.is_certificate_packet(raw_packet) or has_x509_subject:
                    cert_result = self._certificate_parser.extract(raw_packet)
                    break
            except Exception as exc:
                self._logger.debug("Certificate scan error for flow %s: %s", flow_id, exc)

        if client_hello is None and cert_result is None:
            return None

        if client_hello is None and server_hello is not None:
            client_hello = {
                "tls_version": server_hello.get("tls_version"),
                "cipher_suites": [server_hello.get("selected_cipher")] if server_hello.get("selected_cipher") is not None else [],
                "extensions": [],
                "elliptic_curves": [],
            }

        ch = client_hello or {}
        cert = cert_result or {}

        tls_session = TLSSessionRecord(
            session_id=str(uuid.uuid4()),
            flow_id=flow_id,
            sni_domain=self._to_optional_str(ch.get("sni")),
            ja3_hash=ja3_hash,
            tls_version=self._to_optional_int(ch.get("tls_version")),
            cipher_suites=self._to_int_list(ch.get("cipher_suites")),
            extensions=self._to_int_list(ch.get("extensions")),
            elliptic_curves=self._to_int_list(ch.get("elliptic_curves")),
            cert_subject=self._to_optional_str(cert.get("cert_subject")),
            cert_issuer=self._to_optional_str(cert.get("cert_issuer")),
            cert_not_before=self._to_optional_float(cert.get("cert_not_before")),
            cert_not_after=self._to_optional_float(cert.get("cert_not_after")),
            cert_fingerprint=self._to_optional_str(cert.get("cert_fingerprint")),
            cert_san_list=self._to_str_list(cert.get("cert_san_list")),
            cert_is_self_signed=bool(cert.get("cert_is_self_signed", False)),
            created_at=time.time(),
        )

        self._logger.debug(
            "Assembled TLS session for flow %s: SNI=%s, JA3=%s",
            flow_id,
            tls_session.sni_domain,
            ja3_hash[:8] if ja3_hash else None,
        )
        return tls_session

    def assemble_from_flow(
        self, flow_record: FlowRecord, packets: list[dict[str, Any]]
    ) -> TLSSessionRecord | None:
        """Assemble TLS metadata using a FlowRecord instead of a raw flow_id string."""
        return self.assemble(flow_record.flow_id, packets)

    def _to_int_list(self, value: Any) -> list[int]:
        if value is None:
            return []
        if isinstance(value, list):
            parsed: list[int] = []
            for item in value:
                try:
                    parsed.append(int(item))
                except Exception:
                    continue
            return parsed
        try:
            return [int(value)]
        except Exception:
            return []

    def _to_str_list(self, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]

    def _to_optional_str(self, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _to_optional_int(self, value: Any) -> int | None:
        try:
            if value is None:
                return None
            return int(value)
        except Exception:
            return None

    def _to_optional_float(self, value: Any) -> float | None:
        try:
            if value is None:
                return None
            return float(value)
        except Exception:
            return None
