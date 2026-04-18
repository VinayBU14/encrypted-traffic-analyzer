"""Standalone live capture pipeline.

This module wires live packet capture, flow aggregation, and flow scoring into one
blocking runtime pipeline suitable for online monitoring.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from live_flow_aggregator import LiveFlowAggregator
from live_scorer import LiveScorer
from src.ingestion.live_capture import LiveCaptureReader


class LiveCapturePipeline:
    """End-to-end live capture pipeline for packet-to-alert processing.

    The pipeline performs the following sequence:
    1. Capture normalized packets from LiveCaptureReader.
    2. Aggregate packets into timed-out bidirectional flows.
    3. Batch-score completed flows.
    4. Emit alert callbacks for non-benign verdicts.
    """

    def __init__(
        self,
        interface: str = "Wi-Fi",
        mode: str = "supervised",
        model_dir: str = "models/ml",
        project_root: str = ".",
        db_path: str = "spectra.db",
        no_db: bool = False,
        batch_size: int = 10,
        flow_timeout_seconds: float = 60,
        min_packets: int = 2,
        bpf_filter: str = "",
        packet_limit: int = 0,
        on_alert: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        """Initialize all pipeline components and counters.

        Args:
            interface: Capture interface name for LiveCaptureReader.
            mode: Scoring mode, either "supervised" or "unsupervised".
            model_dir: Model directory for supervised scoring artifacts.
            project_root: Project root for resolving unsupervised artifacts.
            db_path: SQLite DB path used by scorer ingestion.
            no_db: When True, skip writing scored rows into DB.
            batch_size: Number of completed flows to batch per scoring call.
            flow_timeout_seconds: Inactivity timeout used for flow completion.
            min_packets: Minimum packets required before a flow is emitted.
            bpf_filter: Optional BPF filter string for packet capture.
            packet_limit: Optional max packets to capture; 0 means unlimited.
            on_alert: Optional callback invoked for each non-benign scored flow.
        """
        self._logger = logging.getLogger(__name__)

        self._capture_reader = LiveCaptureReader(
            interface=interface,
            packet_limit=packet_limit,
            bpf_filter=bpf_filter,
        )
        self._aggregator = LiveFlowAggregator(
            flow_timeout_seconds=flow_timeout_seconds,
            min_packets=min_packets,
        )
        self._scorer = LiveScorer(
            mode=mode,
            model_dir=model_dir,
            project_root=project_root,
            db_path=db_path,
            no_db=no_db,
            batch_size=batch_size,
        )
        self._on_alert = on_alert

        self.packets_captured = 0
        self.flows_completed = 0
        self.flows_scored = 0
        self.alerts_generated = 0

        self._logger.info(
            "Pipeline initialized: interface=%s mode=%s batch_size=%d flow_timeout_seconds=%.2f min_packets=%d",
            interface,
            mode,
            batch_size,
            float(flow_timeout_seconds),
            min_packets,
        )
        self._logger.debug(
            "Capture options: bpf_filter=%r packet_limit=%d no_db=%s",
            bpf_filter,
            packet_limit,
            no_db,
        )

    def run(self) -> None:
        """Run the blocking capture-processing loop until stopped or interrupted.

        The method captures packets continuously, processes completed flows, and
        flushes pending flows/scores on shutdown. A keyboard interrupt is handled
        gracefully and does not suppress final flushing and stats logging.
        """
        self._logger.info("Live capture pipeline started")
        interrupted = False

        try:
            for packet in self._capture_reader.start_capture():
                self.packets_captured += 1
                self._logger.debug(
                    "Packet #%d captured: %s:%s -> %s:%s size=%s",
                    self.packets_captured,
                    packet.get("src_ip"),
                    packet.get("src_port"),
                    packet.get("dst_ip"),
                    packet.get("dst_port"),
                    packet.get("packet_size"),
                )

                completed_flows = self._aggregator.add_packet(packet)
                if completed_flows:
                    self._logger.debug(
                        "Completed flows emitted by aggregator: %d", len(completed_flows)
                    )
                self._process_completed_flows(completed_flows)

        except KeyboardInterrupt:
            interrupted = True
            self._logger.info("KeyboardInterrupt received; stopping capture")
            self.stop()

        finally:
            self._flush_pipeline_buffers()
            if interrupted:
                self._logger.info("Pipeline stopped after interrupt")
            else:
                self._logger.info("Pipeline stopped")
            self._logger.info("Final stats: %s", self.get_stats())

    def stop(self) -> None:
        """Signal the underlying live capture reader to stop."""
        self._logger.info("Stop requested")
        self._capture_reader.stop()

    def get_stats(self) -> dict[str, int]:
        """Return current pipeline counters and active flow count."""
        return {
            "packets_captured": int(self.packets_captured),
            "flows_completed": int(self.flows_completed),
            "flows_scored": int(self.flows_scored),
            "alerts_generated": int(self.alerts_generated),
            "active_flows": int(self._aggregator.get_active_flow_count()),
        }

    @staticmethod
    def list_interfaces() -> list[str]:
        """Return available capture interfaces from LiveCaptureReader."""
        return LiveCaptureReader.get_available_interfaces()

    def _flush_pipeline_buffers(self) -> None:
        """Flush aggregator then scorer so no eligible flow is left unprocessed."""
        remaining_flows = self._aggregator.flush_all()
        if remaining_flows:
            self._logger.info("Flushing %d remaining aggregated flows", len(remaining_flows))
        self._process_completed_flows(remaining_flows)

        remaining_scored = self._scorer.flush()
        if remaining_scored:
            self._logger.info("Flushing %d remaining scored flows", len(remaining_scored))
        self._process_scored_results(remaining_scored)

    def _process_completed_flows(self, completed_flows: list[dict[str, Any]]) -> None:
        """Submit completed flows to scorer and process any immediate scored results."""
        for flow in completed_flows:
            self.flows_completed += 1
            self._logger.debug(
                "Submitting completed flow #%d: flow_id=%s",
                self.flows_completed,
                flow.get("flow_id"),
            )
            scored_results = self._scorer.submit_flow(flow)
            if scored_results:
                self._logger.debug(
                    "Scorer returned %d rows after submission", len(scored_results)
                )
            self._process_scored_results(scored_results)

    def _process_scored_results(self, scored_results: list[dict[str, Any]]) -> None:
        """Update counters and dispatch callbacks for scored non-benign flows."""
        for scored in scored_results:
            self.flows_scored += 1
            verdict = str(scored.get("verdict", "BENIGN"))
            self._logger.debug(
                "Scored flow #%d: verdict=%s src=%s:%s dst=%s:%s",
                self.flows_scored,
                verdict,
                scored.get("src_ip"),
                scored.get("src_port"),
                scored.get("dst_ip"),
                scored.get("dst_port"),
            )

            if verdict != "BENIGN":
                self.alerts_generated += 1
                self._logger.info(
                    "Alert generated #%d: verdict=%s flow_id=%s",
                    self.alerts_generated,
                    verdict,
                    scored.get("flow_id", ""),
                )
                if self._on_alert is not None:
                    try:
                        self._on_alert(scored)
                    except Exception as exc:
                        self._logger.exception("on_alert callback failed: %s", exc)
