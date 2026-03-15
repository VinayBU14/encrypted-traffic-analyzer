
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

            flow_key = self._tracker._build_flow_key(packet)
            completed = self._tracker.add_packet(packet)
            flow_id = self._resolve_flow_id(flow_key, packet, completed)
            if flow_id is not None:
                self._packet_buffer.setdefault(flow_id, []).append(packet)

            for flow in completed:
                self._store.add(flow)
                flows_completed += 1
                tls_session = self._assemble_tls_session(flow)
                if tls_session is not None:
                    pending_tls_sessions.append(tls_session)
                self._compute_feature_row(flow, tls_session)

            if packets_processed % 1000 == 0:
                timed_out_flows = self._tracker.check_timeouts(last_seen_time)
                for flow in timed_out_flows:
                    self._store.add(flow)
                    flows_completed += 1
                    tls_session = self._assemble_tls_session(flow)
                    if tls_session is not None:
                        pending_tls_sessions.append(tls_session)
                    self._compute_feature_row(flow, tls_session)
                self._logger.info(
                    "Processed %d packets; timed out %d flows",
                    packets_processed,
                    len(timed_out_flows),
                )

        timed_out_final = self._tracker.check_timeouts(last_seen_time)
        for flow in timed_out_final:
            self._store.add(flow)
            flows_completed += 1
            tls_session = self._assemble_tls_session(flow)
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
            "Pipeline complete: packets=%d flows_completed=%d flows_saved=%d tls_sessions_saved=%d flushed=%d",
            packets_processed,
            flows_completed,
            flows_saved,
            tls_sessions_saved,
            flushed_now,
        )
        return summary

    def _resolve_flow_id(
        self,
        flow_key: tuple[str, int, str, int, str],
        packet: dict[str, Any],
        completed_flows: list[FlowRecord],
    ) -> str | None:
        active_flow = self._tracker._active_flows.get(flow_key)
        if active_flow is not None:
            return active_flow.flow_id

        src_ip = str(packet.get("src_ip", ""))
        dst_ip = str(packet.get("dst_ip", ""))
        src_port = int(packet.get("src_port", 0))
        dst_port = int(packet.get("dst_port", 0))
        protocol = str(packet.get("protocol", "")).upper()

        for flow in completed_flows:
            same_direction = (
                flow.src_ip == src_ip
                and flow.dst_ip == dst_ip
                and flow.src_port == src_port
                and flow.dst_port == dst_port
            )
            reverse_direction = (
                flow.src_ip == dst_ip
                and flow.dst_ip == src_ip
                and flow.src_port == dst_port
                and flow.dst_port == src_port
            )
            if flow.protocol.upper() == protocol and (same_direction or reverse_direction):
                return flow.flow_id
        return None

    def _assemble_tls_session(self, flow: FlowRecord) -> Any | None:
        packets = self._packet_buffer.pop(flow.flow_id, [])
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
            self._logger.warning("Feature row validation failed for flow %s: %s", flow.flow_id, exc)
            return
        self._feature_rows.append(feature_row)
