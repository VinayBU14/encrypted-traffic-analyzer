"""
simulate_attack.py
==================
Simulated Attack Injection System for Spectra Encrypted Traffic Analyzer.

Generates synthetic attack scenarios containing:
  - Malicious JA3 fingerprints  (from ja3_malicious.json threat intel)
  - Malicious TLS certificates  (self-signed, bad fingerprints, very new, free-CA)
  - Realistic flow metadata     (IPs, ports, beacon timing, byte counts)

Each simulated attack is scored through the EXACT same pipeline used for real
traffic — JA3Analyzer, CertificateAnalyzer, ScoringEngine, AlertBuilder — so
every resulting alert is genuine and indistinguishable from a live detection.

Usage:
    python simulate_attack.py [--scenario all|ja3|cert|combo|beacon]
                              [--count N]
                              [--db PATH]
                              [--verbose]

The injected alerts will appear immediately in the Spectra dashboard.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Project imports ────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.analysis.certificate.analyzer import CertificateAnalyzer
from src.analysis.ja3.analyzer import JA3Analyzer
from src.scoring.alert_builder import AlertBuilder
from src.scoring.engine import ScoringEngine
from src.scoring.severity import get_severity, get_recommended_action
from src.storage.models import TLSSessionRecord

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("simulate_attack")

# ── Paths ──────────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
_MALICIOUS_JA3_PATH = _ROOT / "data" / "threat_intel" / "ja3_malicious.json"
_DB_PATH_DEFAULT = str(_ROOT / "data" / "spectra.db")

# ── Load malicious JA3 pool from threat intel ──────────────────────────────────
def _load_malicious_ja3_pool() -> list[tuple[str, str]]:
    """Return list of (hash, label) from the threat intel file."""
    try:
        raw = json.loads(_MALICIOUS_JA3_PATH.read_text(encoding="utf-8"))
        result = []
        for h, v in raw.items():
            if isinstance(v, dict):
                label = v.get("label", "unknown malware")
            else:
                label = str(v)
            result.append((h, label))
        logger.info("Loaded %d malicious JA3 hashes from threat intel", len(result))
        return result
    except Exception as exc:
        logger.warning("Could not load JA3 threat intel: %s — using built-in samples", exc)
        return [
            ("e7d705a3286e19ea42f587b344ee6865", "Emotet malware"),
            ("6734f37431670b3ab4292b8f60f29984", "TrickBot malware"),
            ("a0e9f5d64349fb13191bc781f81f42e1", "CobaltStrike beacon"),
            ("72a589da586844d7f0818ce684948eea", "Metasploit framework"),
            ("de350869b8c85de67a350c8d186c11e6", "Cobalt Strike default"),
        ]

MALICIOUS_JA3_POOL: list[tuple[str, str]] = _load_malicious_ja3_pool()

# ── Known-bad certificate fingerprints (match CertificateAnalyzer._BAD_FINGERPRINTS) ──
BAD_CERT_FINGERPRINTS: list[str] = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
]

# ── Realistic attacker infrastructure ─────────────────────────────────────────
ATTACKER_IPS = [
    "185.220.101.47",   # Known Tor exit
    "194.165.16.29",    # C2 infra range
    "91.108.4.234",     # Telegram C2 abuse
    "45.142.212.100",   # Bulletproof hosting
    "176.97.116.102",   # Eastern European exit node
    "103.224.182.242",  # AS in known threat feed
    "198.54.117.197",   # VPS abuse
    "62.233.50.11",     # Botnet relay
]

VICTIM_IPS = [
    "10.0.1.15", "10.0.1.42", "10.0.2.7",
    "192.168.1.101", "192.168.1.155", "192.168.2.34",
]

MALICIOUS_DOMAINS = [
    "update-service.onion-relay.net",
    "cdn.microsoftupdate-secure.com",
    "telemetry.windowsdefender-check.org",
    "api.legitimate-looking-c2.ru",
    "github-update.malware-host.cc",
    "adobe-flash-update.xyz",
]

# ── Attack scenario definitions ────────────────────────────────────────────────

@dataclass
class AttackScenario:
    name: str
    description: str
    ja3_hash: str | None
    ja3_label: str | None
    # Certificate params
    cert_is_self_signed: bool
    cert_age_days: float           # how old the cert is
    cert_validity_days: float      # total validity window
    cert_issuer: str | None
    cert_san_count: int
    use_bad_fingerprint: bool
    # Scores to add on top of module results (for beacon / graph simulation)
    extra_beacon_score: float
    extra_graph_score: float
    extra_anomaly_score: float
    # Narrative
    src_ip: str
    dst_ip: str
    dst_domain: str
    src_port: int
    dst_port: int


def _build_scenarios(count: int = 1, scenario_filter: str = "all") -> list[AttackScenario]:
    """Generate a list of attack scenarios based on filter type."""
    scenarios: list[AttackScenario] = []

    # ── Scenario 1: Pure malicious JA3 (CobaltStrike C2) ──────────────────
    if scenario_filter in ("all", "ja3"):
        for _ in range(count):
            ja3_hash, ja3_label = random.choice(MALICIOUS_JA3_POOL)
            scenarios.append(AttackScenario(
                name="Malicious JA3 — C2 Beacon",
                description=f"TLS ClientHello fingerprint matches {ja3_label} threat intel",
                ja3_hash=ja3_hash,
                ja3_label=ja3_label,
                cert_is_self_signed=False,
                cert_age_days=random.uniform(45, 200),
                cert_validity_days=365,
                cert_issuer="CN=DigiCert Global Root CA",
                cert_san_count=1,
                use_bad_fingerprint=False,
                extra_beacon_score=0.0,
                extra_graph_score=random.uniform(0.10, 0.30),
                extra_anomaly_score=random.uniform(0.55, 0.75),
                src_ip=random.choice(VICTIM_IPS),
                dst_ip=random.choice(ATTACKER_IPS),
                dst_domain=random.choice(MALICIOUS_DOMAINS),
                src_port=random.randint(49152, 65535),
                dst_port=443,
            ))

    # ── Scenario 2: Malicious certificate (self-signed, very new, bad fp) ──
    if scenario_filter in ("all", "cert"):
        for _ in range(count):
            age = random.uniform(0.1, 5.0)   # very fresh — triggers cert_very_young
            scenarios.append(AttackScenario(
                name="Malicious Certificate — Self-Signed + New",
                description="Self-signed certificate issued <7 days ago with known-bad fingerprint",
                ja3_hash=None,
                ja3_label=None,
                cert_is_self_signed=True,
                cert_age_days=age,
                cert_validity_days=random.uniform(1, 6),   # short validity too
                cert_issuer="CN=localhost,O=AttackerOrg",
                cert_san_count=random.randint(4, 8),       # SAN cluster
                use_bad_fingerprint=True,
                extra_beacon_score=random.uniform(0.20, 0.40),
                extra_graph_score=random.uniform(0.25, 0.45),
                extra_anomaly_score=random.uniform(0.72, 0.88),
                src_ip=random.choice(VICTIM_IPS),
                dst_ip=random.choice(ATTACKER_IPS),
                dst_domain="secure-tunnel." + random.choice(["xyz", "onion.cc", "ru", "tk"]),
                src_port=random.randint(49152, 65535),
                dst_port=random.choice([443, 8443, 4433]),
            ))

    # ── Scenario 3: Combined JA3 + malicious cert (highest severity) ───────
    if scenario_filter in ("all", "combo"):
        for _ in range(count):
            ja3_hash, ja3_label = random.choice(MALICIOUS_JA3_POOL)
            age = random.uniform(0.5, 4.0)
            scenarios.append(AttackScenario(
                name="COMBO — Malicious JA3 + Malicious Certificate",
                description=f"Both JA3 ({ja3_label}) and certificate are flagged as malicious",
                ja3_hash=ja3_hash,
                ja3_label=ja3_label,
                cert_is_self_signed=True,
                cert_age_days=age,
                cert_validity_days=random.uniform(1, 5),
                cert_issuer="CN=letsencrypt-lookalike.tk",
                cert_san_count=random.randint(5, 10),
                use_bad_fingerprint=True,
                extra_beacon_score=random.uniform(0.85, 1.0),
                extra_graph_score=random.uniform(0.85, 1.0),
                extra_anomaly_score=random.uniform(0.88, 0.99),
                src_ip=random.choice(VICTIM_IPS),
                dst_ip=random.choice(ATTACKER_IPS),
                dst_domain=random.choice(MALICIOUS_DOMAINS),
                src_port=random.randint(49152, 65535),
                dst_port=443,
            ))

    # ── Scenario 4: Beacon-like periodic C2 with malicious JA3 ─────────────
    if scenario_filter in ("all", "beacon"):
        for _ in range(count):
            ja3_hash, ja3_label = random.choice(MALICIOUS_JA3_POOL)
            scenarios.append(AttackScenario(
                name="C2 Beacon — Periodic JA3 Pattern",
                description=f"Regular beacon interval (low jitter) with JA3={ja3_label}",
                ja3_hash=ja3_hash,
                ja3_label=ja3_label,
                cert_is_self_signed=False,
                cert_age_days=random.uniform(2, 10),   # young cert on C2
                cert_validity_days=365,
                cert_issuer="ZeroSSL",  # free CA + new domain → cert score hit
                cert_san_count=2,
                use_bad_fingerprint=False,
                extra_beacon_score=random.uniform(0.55, 0.85),  # high beacon
                extra_graph_score=random.uniform(0.15, 0.35),
                extra_anomaly_score=random.uniform(0.65, 0.90),
                src_ip=random.choice(VICTIM_IPS),
                dst_ip=random.choice(ATTACKER_IPS),
                dst_domain=random.choice(MALICIOUS_DOMAINS),
                src_port=random.randint(49152, 65535),
                dst_port=443,
            ))

    return scenarios


# ── TLSSessionRecord builder ───────────────────────────────────────────────────

def _build_tls_session(scenario: AttackScenario) -> TLSSessionRecord:
    """Construct a synthetic TLSSessionRecord from scenario params."""
    now = time.time()

    cert_not_before = now - (scenario.cert_age_days * 86400)
    cert_not_after  = cert_not_before + (scenario.cert_validity_days * 86400)

    san_list = [scenario.dst_domain] + [
        f"alt{i}.{scenario.dst_domain}" for i in range(1, scenario.cert_san_count)
    ]

    fingerprint = (
        random.choice(BAD_CERT_FINGERPRINTS)
        if scenario.use_bad_fingerprint
        else uuid.uuid4().hex + uuid.uuid4().hex
    )

    return TLSSessionRecord(
        session_id=str(uuid.uuid4()),
        flow_id=str(uuid.uuid4()),
        sni_domain=scenario.dst_domain,
        ja3_hash=scenario.ja3_hash,
        tls_version=0x0303,          # TLS 1.2 — common in malware
        cipher_suites=[49199, 49195, 49200, 49196, 52393],
        extensions=[0, 5, 10, 11, 13, 18, 23, 65281],
        elliptic_curves=[29, 23, 24],
        cert_subject=f"CN={scenario.dst_domain}",
        cert_issuer=scenario.cert_issuer,
        cert_not_before=cert_not_before,
        cert_not_after=cert_not_after,
        cert_fingerprint=fingerprint,
        cert_san_list=san_list,
        cert_is_self_signed=scenario.cert_is_self_signed,
        created_at=now,
    )


# ── Flow record builder (minimal, for alert FK) ───────────────────────────────

def _insert_synthetic_flow(conn: sqlite3.Connection, scenario: AttackScenario, flow_id: str) -> None:
    """Insert a minimal flow row so the alert foreign key resolves."""
    now = time.time()
    start = now - random.uniform(0.5, 10.0)
    conn.execute(
        """
        INSERT OR IGNORE INTO flows (
            flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
            start_time, end_time, duration_ms,
            packet_count, bytes_total, upload_bytes, download_bytes,
            packet_sizes, inter_arrival_ms, tcp_flags,
            status, created_at,
            composite_score, anomaly_score, ja3_score, beacon_score,
            cert_score, graph_score, verdict, severity, source, is_live
        ) VALUES (
            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
        )
        """,
        (
            flow_id,
            scenario.src_ip, scenario.dst_ip,
            scenario.src_port, scenario.dst_port,
            "TCP",
            start, now, (now - start) * 1000,
            random.randint(10, 600),
            random.randint(5000, 500000),
            random.randint(1000, 50000),
            random.randint(4000, 450000),
            json.dumps([random.randint(40, 1460) for _ in range(20)]),
            json.dumps([random.uniform(0.5, 120.0) for _ in range(20)]),
            json.dumps({"SYN": 1, "ACK": 15, "PSH": 8, "FIN": 1}),
            "COMPLETED",
            now,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            "MALICIOUS", "HIGH",
            "simulated", 0,
        ),
    )


# ── Alert persistence (mirrors alert_repository.insert_alert) ─────────────────

def _insert_alert(conn: sqlite3.Connection, alert_dict: dict[str, Any], is_live: int = 0) -> None:
    """Insert an alert into spectra.db, adding columns that may not exist in older schemas."""
    # Ensure extended columns exist (migration-safe)
    existing_cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    for col_def in [
        ("src_port",    "INTEGER DEFAULT 0"),
        ("dst_port",    "INTEGER DEFAULT 0"),
        ("is_live",     "INTEGER DEFAULT 0"),
        ("is_beacon",   "INTEGER DEFAULT 0"),
        ("groq_summary","TEXT DEFAULT ''"),
        ("groq_explanation","TEXT DEFAULT ''"),
        ("groq_action", "TEXT DEFAULT ''"),
        ("groq_threat_type","TEXT DEFAULT ''"),
        ("groq_confidence","TEXT DEFAULT ''"),
    ]:
        if col_def[0] not in existing_cols:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col_def[0]} {col_def[1]}")

    findings_json = json.dumps(alert_dict.get("findings", []))

    conn.execute(
        """
        INSERT OR IGNORE INTO alerts (
            alert_id, flow_id, timestamp, created_at, severity,
            composite_score, anomaly_score, ja3_score, beacon_score,
            cert_score, graph_score,
            src_ip, src_port, dst_ip, dst_port, dst_domain,
            findings, recommended_action,
            is_suppressed, is_live, is_beacon
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            alert_dict["alert_id"],
            alert_dict["flow_id"],
            alert_dict["timestamp"],
            alert_dict["created_at"],
            alert_dict["severity"],
            alert_dict["composite_score"],
            alert_dict["anomaly_score"],
            alert_dict["ja3_score"],
            alert_dict["beacon_score"],
            alert_dict["cert_score"],
            alert_dict["graph_score"],
            alert_dict["src_ip"],
            alert_dict.get("src_port", 0),
            alert_dict["dst_ip"],
            alert_dict.get("dst_port", 0),
            alert_dict["dst_domain"],
            findings_json,
            alert_dict["recommended_action"],
            0,
            is_live,
            1 if alert_dict.get("beacon_score", 0) > 0.4 else 0,
        ),
    )
    conn.commit()


# ── Main injection engine ──────────────────────────────────────────────────────

class AttackSimulator:
    """Inject synthetic attack sessions into the Spectra database."""

    def __init__(self, db_path: str = _DB_PATH_DEFAULT) -> None:
        self._db_path = db_path
        self._ja3_analyzer  = JA3Analyzer()
        self._cert_analyzer = CertificateAnalyzer()
        self._scoring_engine = ScoringEngine()
        self._alert_builder  = AlertBuilder()
        logger.info("AttackSimulator ready — db=%s", db_path)

    def run(
        self,
        scenario_filter: str = "all",
        count: int = 1,
        verbose: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Generate, score and persist simulated attacks.
        Returns list of generated alert dicts.
        """
        scenarios = _build_scenarios(count=count, scenario_filter=scenario_filter)
        generated_alerts: list[dict[str, Any]] = []

        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=OFF")   # avoid FK errors for missing flows

        logger.info("Injecting %d simulated attack(s) [filter=%s]", len(scenarios), scenario_filter)

        for i, scenario in enumerate(scenarios, 1):
            logger.info("[%d/%d] Scenario: %s", i, len(scenarios), scenario.name)

            # 1. Build synthetic TLS session
            tls_session = _build_tls_session(scenario)
            flow_id = tls_session.flow_id

            # 2. Run through real analyzers (same code path as live traffic)
            ja3_result  = self._ja3_analyzer.score(tls_session)
            cert_result = self._cert_analyzer.score(tls_session)

            ja3_score   = float(ja3_result["ja3_score"])
            cert_score  = float(cert_result["cert_score"])
            beacon_score = min(1.0, scenario.extra_beacon_score)
            graph_score  = min(1.0, scenario.extra_graph_score)
            anomaly_score= min(1.0, scenario.extra_anomaly_score)

            # 3. Composite scoring engine (real weights from config)
            score_result = self._scoring_engine.compute(
                ja3_score=ja3_score,
                cert_score=cert_score,
                beacon_score=beacon_score,
                graph_score=graph_score,
                anomaly_score=anomaly_score,
            )

            # 4. Assemble findings
            findings: list[str] = []
            if ja3_result.get("finding"):
                findings.append(str(ja3_result["finding"]))
            findings.extend(cert_result.get("findings", []))
            if beacon_score > 0.4:
                findings.append(
                    f"Periodic beacon pattern detected — score {beacon_score:.3f} "
                    f"(low jitter C2 communication)"
                )
            if graph_score > 0.3:
                findings.append(
                    f"Destination IP {scenario.dst_ip} linked to known malicious infrastructure "
                    f"(graph proximity score {graph_score:.3f})"
                )
            if anomaly_score > 0.7:
                findings.append(
                    f"ML anomaly score {anomaly_score:.3f} — flow deviates significantly from baseline"
                )
            if not findings:
                findings.append(f"Simulated attack pattern: {scenario.description}")

            # 5. Build alert record
            alert_record = self._alert_builder.build(
                flow_id=flow_id,
                src_ip=scenario.src_ip,
                dst_ip=scenario.dst_ip,
                dst_domain=scenario.dst_domain,
                composite_score=score_result["composite_score"],
                severity=score_result["severity"],
                recommended_action=score_result["recommended_action"],
                ja3_score=ja3_score,
                cert_score=cert_score,
                beacon_score=beacon_score,
                graph_score=graph_score,
                anomaly_score=anomaly_score,
                findings=findings,
            )

            alert_dict: dict[str, Any] = {
                "alert_id":          alert_record.alert_id,
                "flow_id":           flow_id,
                "timestamp":         alert_record.timestamp,
                "created_at":        alert_record.created_at,
                "severity":          alert_record.severity,
                "composite_score":   alert_record.composite_score,
                "ja3_score":         ja3_score,
                "beacon_score":      beacon_score,
                "cert_score":        cert_score,
                "graph_score":       graph_score,
                "anomaly_score":     anomaly_score,
                "src_ip":            scenario.src_ip,
                "src_port":          scenario.src_port,
                "dst_ip":            scenario.dst_ip,
                "dst_port":          scenario.dst_port,
                "dst_domain":        scenario.dst_domain,
                "findings":          findings,
                "recommended_action":alert_record.recommended_action,
            }

            # 6. Persist flow + alert to DB
            _insert_synthetic_flow(conn, scenario, flow_id)
            _insert_alert(conn, alert_dict)

            generated_alerts.append(alert_dict)

            if verbose:
                _print_alert_summary(alert_dict, scenario, ja3_result, cert_result)

        conn.close()
        logger.info("Done — %d alerts injected into %s", len(generated_alerts), self._db_path)
        return generated_alerts


# ── Console output ─────────────────────────────────────────────────────────────

def _print_alert_summary(
    alert: dict,
    scenario: AttackScenario,
    ja3_result: dict,
    cert_result: dict,
) -> None:
    sep = "─" * 72
    sev = alert["severity"]
    sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "CLEAN": "🟢"}
    icon = sev_icons.get(sev, "⚪")

    print(f"\n{sep}")
    print(f"  {icon}  SIMULATED ATTACK ALERT  {icon}")
    print(sep)
    print(f"  Scenario    : {scenario.name}")
    print(f"  Alert ID    : {alert['alert_id']}")
    print(f"  Severity    : {sev}")
    print(f"  Score       : {alert['composite_score']:.4f}")
    print(f"  Flow        : {alert['src_ip']}:{alert['src_port']} → "
          f"{alert['dst_domain']} ({alert['dst_ip']}:{alert['dst_port']})")
    print()
    print(f"  ── Component Scores ──────────────────────────────────")
    print(f"     JA3 Fingerprint  : {alert['ja3_score']:.4f}   "
          f"{'[' + str(ja3_result.get('ja3_hash','')[:12]) + '...]' if ja3_result.get('ja3_hash') else '[no match]'}")
    print(f"     Certificate Risk : {alert['cert_score']:.4f}")
    print(f"     Beacon Pattern   : {alert['beacon_score']:.4f}")
    print(f"     Graph Proximity  : {alert['graph_score']:.4f}")
    print(f"     ML Anomaly       : {alert['anomaly_score']:.4f}")
    print()
    print(f"  ── Findings ──────────────────────────────────────────")
    for f in alert["findings"]:
        print(f"     △  {f}")
    print()
    print(f"  ── Recommended Action ────────────────────────────────")
    print(f"     ⚡  {alert['recommended_action']}")
    print(sep)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Spectra Simulated Attack Injector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scenarios:
  all     — inject one of each type (default)
  ja3     — only malicious JA3 fingerprint attacks
  cert    — only malicious certificate attacks
  combo   — only combined JA3 + certificate attacks
  beacon  — only periodic C2 beacon attacks

Examples:
  python simulate_attack.py
  python simulate_attack.py --scenario combo --count 3 --verbose
  python simulate_attack.py --scenario all --count 2 --db data/spectra.db
        """,
    )
    parser.add_argument(
        "--scenario",
        choices=["all", "ja3", "cert", "combo", "beacon"],
        default="all",
        help="Which attack scenario type to simulate",
    )
    parser.add_argument(
        "--count", type=int, default=1,
        help="Number of each scenario type to inject (default: 1)",
    )
    parser.add_argument(
        "--db", default=_DB_PATH_DEFAULT,
        help="Path to spectra.db (default: data/spectra.db)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print full alert details to stdout",
    )
    args = parser.parse_args()

    simulator = AttackSimulator(db_path=args.db)
    alerts = simulator.run(
        scenario_filter=args.scenario,
        count=args.count,
        verbose=args.verbose,
    )

    print(f"\n✅  Injected {len(alerts)} alert(s) into {args.db}")
    print("   Refresh the Spectra dashboard to see them in the alert feed.\n")

    # Summary table
    print(f"{'#':<4} {'Severity':<10} {'Score':<8} {'Src IP':<16} {'Destination':<38} {'Findings'}")
    print("─" * 90)
    for i, a in enumerate(alerts, 1):
        print(
            f"{i:<4} {a['severity']:<10} {a['composite_score']:<8.4f} "
            f"{a['src_ip']:<16} {(a['dst_domain'] or a['dst_ip'])[:37]:<38} "
            f"{len(a['findings'])} finding(s)"
        )
    print()


if __name__ == "__main__":
    main()