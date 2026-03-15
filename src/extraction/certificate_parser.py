
"""TLS certificate metadata extraction from observable handshake fields."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

from cryptography import x509


class CertificateParser:
    """Extract certificate metadata from TLS packets with partial-result resilience."""

    def __init__(self) -> None:
        """Initialize certificate parser logger."""
        self._logger = logging.getLogger(__name__)

    def extract(self, raw_packet: object) -> dict[str, Any] | None:
        """Extract certificate fields from a packet and return partial results when available."""
        result: dict[str, Any] = {
            "cert_subject": None,
            "cert_issuer": None,
            "cert_not_before": None,
            "cert_not_after": None,
            "cert_fingerprint": None,
            "cert_san_list": [],
            "cert_is_self_signed": False,
            "cert_validity_days": None,
        }

        tls_layer: Any | None = None
        try:
            tls_layer = getattr(raw_packet, "tls")
        except Exception as exc:
            self._logger.debug("Certificate field tls_layer not available: %s", exc)
            return None

        # Subject CN
        try:
            subject_value = getattr(tls_layer, "x509sat_utf8string", None)
            if isinstance(subject_value, str) and "," in subject_value:
                subject_value = subject_value.split(",")[0].strip()
            if subject_value is not None:
                result["cert_subject"] = str(subject_value).strip()
            else:
                self._logger.debug("Certificate field cert_subject not available: missing x509sat_utf8string")
        except Exception as exc:
            self._logger.debug("Certificate field cert_subject not available: %s", exc)

        # Issuer
        try:
            issuer_value = getattr(tls_layer, "x509af_issuer", None)
            if issuer_value is None:
                issuer_value = getattr(tls_layer, "x509if_rdnsequence", None)
            if issuer_value is not None:
                result["cert_issuer"] = str(issuer_value).strip()
            else:
                self._logger.debug("Certificate field cert_issuer not available: missing issuer fields")
        except Exception as exc:
            self._logger.debug("Certificate field cert_issuer not available: %s", exc)

        # Not Before
        try:
            not_before_raw = getattr(tls_layer, "x509af_notbefore", None)
            if not_before_raw is None:
                utctime = getattr(tls_layer, "x509af_utctime", None)
                if isinstance(utctime, str) and "," in utctime:
                    not_before_raw = utctime.split(",")[0].strip()
                else:
                    not_before_raw = utctime
            if not_before_raw is not None:
                result["cert_not_before"] = self._parse_cert_date(str(not_before_raw))
            else:
                self._logger.debug("Certificate field cert_not_before not available: missing date fields")
        except Exception as exc:
            self._logger.debug("Certificate field cert_not_before not available: %s", exc)

        # Not After
        try:
            not_after_raw = getattr(tls_layer, "x509af_notafter", None)
            if not_after_raw is None:
                utctime = getattr(tls_layer, "x509af_utctime", None)
                if isinstance(utctime, str) and "," in utctime:
                    parts = [item.strip() for item in utctime.split(",") if item.strip()]
                    not_after_raw = parts[1] if len(parts) > 1 else None
            if not_after_raw is not None:
                result["cert_not_after"] = self._parse_cert_date(str(not_after_raw))
            else:
                self._logger.debug("Certificate field cert_not_after not available: missing date fields")
        except Exception as exc:
            self._logger.debug("Certificate field cert_not_after not available: %s", exc)

        # Fingerprint from handshake_certificate
        cert_bytes: bytes | None = None
        try:
            cert_hex = getattr(tls_layer, "handshake_certificate", None)
            if isinstance(cert_hex, str) and cert_hex.strip():
                normalized_hex = cert_hex.replace(":", "").replace(" ", "").strip()
                cert_bytes = bytes.fromhex(normalized_hex)
            if cert_bytes:
                result["cert_fingerprint"] = hashlib.sha256(cert_bytes).hexdigest()
            else:
                self._logger.debug(
                    "Certificate field cert_fingerprint not available: missing handshake_certificate"
                )
        except Exception as exc:
            self._logger.debug("Certificate field cert_fingerprint not available: %s", exc)

        # Parse DER certificate bytes when available for robust date extraction.
        try:
            if cert_bytes:
                cert = x509.load_der_x509_certificate(cert_bytes)
                if result["cert_subject"] is None:
                    result["cert_subject"] = cert.subject.rfc4514_string()
                if result["cert_issuer"] is None:
                    result["cert_issuer"] = cert.issuer.rfc4514_string()

                not_before_dt = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(
                    tzinfo=timezone.utc
                )
                not_after_dt = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
                    tzinfo=timezone.utc
                )
                result["cert_not_before"] = float(not_before_dt.timestamp())
                result["cert_not_after"] = float(not_after_dt.timestamp())
        except Exception as exc:
            self._logger.debug("Certificate DER parse not available: %s", exc)

        # SAN list
        try:
            san_raw = getattr(tls_layer, "x509ce_dnsname", None)
            san_list: list[str] = []
            if isinstance(san_raw, str):
                san_list = [item.strip() for item in san_raw.split(",") if item.strip()]
            elif isinstance(san_raw, (list, tuple, set)):
                san_list = [str(item).strip() for item in san_raw if str(item).strip()]
            result["cert_san_list"] = san_list
            if not san_list:
                self._logger.debug("Certificate field cert_san_list not available: empty")
        except Exception as exc:
            self._logger.debug("Certificate field cert_san_list not available: %s", exc)

        # Self-signed check
        try:
            subject_attr = getattr(tls_layer, "x509af_subject", None)
            issuer_attr = getattr(tls_layer, "x509af_issuer", None)
            subject = str(subject_attr).strip() if subject_attr is not None else None
            issuer = str(issuer_attr).strip() if issuer_attr is not None else None
            subject_cn = str(result["cert_subject"]).strip() if result["cert_subject"] is not None else None
            if subject and issuer:
                result["cert_is_self_signed"] = subject == issuer
            elif subject_cn and issuer:
                result["cert_is_self_signed"] = subject_cn == issuer
        except Exception as exc:
            self._logger.debug("Certificate field cert_is_self_signed not available: %s", exc)

        # Validity days
        try:
            not_before = result["cert_not_before"]
            not_after = result["cert_not_after"]
            if isinstance(not_before, float) and isinstance(not_after, float):
                result["cert_validity_days"] = max(0, int((not_after - not_before) // 86400))
            else:
                self._logger.debug("Certificate field cert_validity_days not available: missing dates")
        except Exception as exc:
            self._logger.debug("Certificate field cert_validity_days not available: %s", exc)

        has_any_data = any(
            [
                result["cert_subject"] is not None,
                result["cert_issuer"] is not None,
                result["cert_not_before"] is not None,
                result["cert_not_after"] is not None,
                result["cert_fingerprint"] is not None,
                len(result["cert_san_list"]) > 0,
            ]
        )
        return result if has_any_data else None

    def _parse_cert_date(self, date_str: str) -> float | None:
        """Parse certificate date strings into Unix timestamps."""
        text = date_str.strip()
        if not text:
            return None

        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%Y%m%d%H%M%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(text, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except Exception:
                continue

        try:
            iso_text = text.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return None
