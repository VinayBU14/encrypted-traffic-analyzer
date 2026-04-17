"""Central offline pipeline orchestrator for Spectra V1 PCAP processing."""

from __future__ import annotations

import logging
import time
from typing import Any

from src.extraction.metadata_assembler import MetadataAssembler
from src.features.certificate_features import CertificateFeatureScorer
from src.features.feature_validator import validate_row
from src.features.flow_features import FlowFeatureExtractor
from src.features.schema import SCHEMA_VERSION
from src.features.tls_features import TLSFeatureExtractor
from src.flow.flow_store import FlowStore
from src.flow.flow_tracker import FlowTracker
from src.ingestion.pcap_reader import PCAPReader
from src.storage.database import get_db
from src.storage.models import FlowRecord
from src.storage.repositories import session_repository


class PipelineOrchestrator:
    """Coordinate ingestion, flow reconstruction, and flow persistence stages."""

    def __init__(self, pcap_path: str) -> None:
        """Initialize orchestrator pipeline components for a PCAP path."""
        self._pcap_path = pcap_path
        self._reader = PCAPReader(pcap_path)
        self._tracker = FlowTracker()
        self._assembler = MetadataAssembler()
        self._flow_features = FlowFeatureExtractor()
        self._tls_features = TLSFeatureExtractor()
        self._cert_scorer = CertificateFeatureScorer()
        self._store = FlowStore()

        # FIXED: key by canonical flow-key STRING (not flow_id).
        # Previously keyed by flow_id which was only resolvable while flow was
        # still active; once a flow completed and was removed from _active_flows,
        # _resolve_flow_id returned None → packets were buffered under None →
        # TLS metadata was never assembled → ja3/cert always 0 → MEDIUM bias.
        self._packet_buffer: dict[str, list[dict[str, Any]]] = {}
        self._feature_rows: list[dict[str, Any]] = []
        self._logger = logging.getLogger(__name__)

    def run(self) -> dict[str, Any]:
        """Execute the offline PCAP pipeline and return a processing summary."""
        self._logger.info("Pipeline starting: %s", self._pcap_path)
        packets_processed = 0
        flows_completed = 0
        tls_sessions_saved = 0
        last_seen_time = time.time()
        session_conn = get_db().get_connection()
        pending_tls_sessions: list[Any] = []
        self._feature_rows.clear()

        for packet in self._reader.read_packets():
            packets_processed += 1
            last_seen_time = float(packet.get("timestamp", last_seen_time))
            self._logger.debug("Processing packet #%d", packets_processed)

            # Build canonical key BEFORE add_packet mutates tracker state
            flow_key = self._tracker._build_flow_key(packet)
            flow_key_str = str(flow_key)

            completed = self._tracker.add_packet(packet)

            # FIXED: Buffer under the canonical flow key string.
            # This works whether the flow is still active or just completed.
            self._packet_buffer.setdefault(flow_key_str, []).append(packet)

            for flow in completed:
                self._store.add(flow)
                flows_completed += 1
                tls_session = self._assemble_tls_session_by_key(flow, flow_key_str)
                if tls_session is not None:
                    pending_tls_sessions.append(tls_session)
                self._compute_feature_row(flow, tls_session)

            if packets_processed % 1000 == 0:
                timed_out_flows = self._tracker.check_timeouts(last_seen_time)
                for flow in timed_out_flows:
                    self._store.add(flow)
                    flows_completed += 1
                    # Rebuild key for timed-out flow from its stored fields
                    timed_key_str = self._key_str_from_flow(flow)
                    tls_session = self._assemble_tls_session_by_key(flow, timed_key_str)
                    if tls_session is not None:
                        pending_tls_sessions.append(tls_session)
                    self._compute_feature_row(flow, tls_session)
                self._logger.info(
                    "Processed %d packets; timed out %d flows",
                    packets_processed,
                    len(timed_out_flows),
                )

        # FIXED: Force-flush ALL remaining active flows.
        # Previously used last_seen_time which only timed out flows that exceeded
        # flow_timeout_seconds. By advancing far beyond the timeout we guarantee
        # every open flow is finalized — critical for short captures or pcap files
        # that end mid-session.
        force_flush_time = last_seen_time + self._tracker.flow_timeout_seconds + 1.0
        timed_out_final = self._tracker.check_timeouts(force_flush_time)
        for flow in timed_out_final:
            self._store.add(flow)
            flows_completed += 1
            timed_key_str = self._key_str_from_flow(flow)
            tls_session = self._assemble_tls_session_by_key(flow, timed_key_str)
            if tls_session is not None:
                pending_tls_sessions.append(tls_session)
            self._compute_feature_row(flow, tls_session)

        flushed_now = self._store.flush_all()
        for tls_session in pending_tls_sessions:
            try:
                session_repository.insert_tls_session(session_conn, tls_session)
                tls_sessions_saved += 1
            except Exception as exc:
                self._logger.error(
                    "Failed to persist TLS session for flow %s: %s",
                    tls_session.flow_id,
                    exc,
                )

        flows_saved = self._store.get_stats()["total_saved"]
        ingestion_stats = self._reader.packet_filter.get_stats()
        flow_stats = self._tracker.get_stats()

        summary = {
            "pcap_path": self._pcap_path,
            "packets_processed": packets_processed,
            "flows_completed": flows_completed,
            "flows_saved": flows_saved,
            "tls_sessions_saved": tls_sessions_saved,
            "feature_rows_computed": len(self._feature_rows),
            "ingestion_stats": ingestion_stats,
            "flow_stats": flow_stats,
        }

        self._logger.info(
            "Pipeline complete: packets=%d flows_completed=%d flows_saved=%d "
            "tls_sessions_saved=%d flushed=%d feature_rows=%d",
            packets_processed,
            flows_completed,
            flows_saved,
            tls_sessions_saved,
            flushed_now,
            len(self._feature_rows),
        )
        return summary

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _key_str_from_flow(self, flow: FlowRecord) -> str:
        """Reconstruct the canonical flow-key string from a FlowRecord.

        The tracker builds keys by sorting IPs so canonical order is
        (lower_ip, lower_port, higher_ip, higher_port, proto).
        We replicate that here so we can look up the packet buffer.
        """
        import ipaddress
        try:
            src_obj = ipaddress.ip_address(flow.src_ip)
            dst_obj = ipaddress.ip_address(flow.dst_ip)
            if src_obj < dst_obj:
                key = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol.upper())
            elif src_obj == dst_obj:
                if flow.src_port <= flow.dst_port:
                    key = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol.upper())
                else:
                    key = (flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, flow.protocol.upper())
            else:
                key = (flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, flow.protocol.upper())
        except Exception:
            key = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol.upper())
        return str(key)

    def _assemble_tls_session_by_key(
        self, flow: FlowRecord, flow_key_str: str
    ) -> Any | None:
        """Pop buffered packets for this flow and assemble TLS metadata."""
        packets = self._packet_buffer.pop(flow_key_str, [])
        if not packets:
            self._logger.debug("No buffered packets for flow %s", flow.flow_id)
        tls_session = self._assembler.assemble(flow.flow_id, packets)
        return tls_session

    def _compute_feature_row(self, flow: FlowRecord, tls_session: Any | None) -> None:
        flow_feats = self._flow_features.extract(flow)
        tls_feats = self._tls_features.extract(tls_session)
        cert_feats = self._cert_scorer.score(tls_session)

        feature_row: dict[str, Any] = {
            "flow_id": flow.flow_id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "schema_version": SCHEMA_VERSION,
            **flow_feats,
            **tls_feats,
            **cert_feats,
        }
        try:
            validate_row(feature_row)
        except (ValueError, TypeError) as exc:
            self._logger.warning(
                "Feature row validation failed for flow %s: %s", flow.flow_id, exc
            )
            return
        self._feature_rows.append(feature_row)