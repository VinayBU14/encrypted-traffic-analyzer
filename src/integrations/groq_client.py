"""
src/integrations/groq_client.py
Groq AI threat analysis — triggered for HIGH and CRITICAL alerts.

Fixes in this version:
  - Updated models: llama3-70b-8192 and llama3-8b-8192 are DECOMMISSIONED.
    Primary model is now llama-3.3-70b-versatile, fallback is llama-3.1-8b-instant.
  - Handles 'model_decommissioned' error code explicitly — immediately falls back
    instead of retrying the dead model.
  - _client is reset on decommission errors so next call re-initialises cleanly.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

GROQ_API_KEY       = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL         = "llama-3.3-70b-versatile"    # replaces decommissioned llama3-70b-8192
GROQ_FALLBACK      = "llama-3.1-8b-instant"        # replaces decommissioned llama3-8b-8192
TRIGGER_SEVERITIES = {"HIGH", "CRITICAL"}

_client = None


def is_configured() -> bool:
    return bool(GROQ_API_KEY)


def _get_client():
    global _client
    if _client:
        return _client
    if not GROQ_API_KEY:
        raise EnvironmentError("GROQ_API_KEY not set in .env")
    try:
        from groq import Groq
        _client = Groq(api_key=GROQ_API_KEY)
        return _client
    except ImportError:
        raise ImportError("groq not installed. Run: pip install groq")


def _build_prompt(alert: dict) -> str:
    findings = alert.get("findings", [])
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except Exception:
            findings = [findings]
    findings_text = "\n".join(f"  - {f}" for f in findings) if findings else "  - No explicit findings"
    src = "LIVE TRAFFIC" if alert.get("is_live") else "PCAP ANALYSIS"

    return f"""You are SPECTRA, a network security AI analyst specialising in encrypted traffic.
Analyse this {alert.get('severity')} alert. Respond ONLY with a JSON object — no markdown, no preamble.

=== ALERT ===
Source: {src}
Severity: {alert.get('severity')}
Flow: {alert.get('src_ip')}:{alert.get('src_port', '')} → {alert.get('dst_ip')}:{alert.get('dst_port', '')}
Composite Score: {alert.get('composite_score', 0):.3f}

Scores:
  anomaly={alert.get('anomaly_score', 0):.3f}  beacon={alert.get('beacon_score', 0):.3f}
  ja3={alert.get('ja3_score', 0):.3f}  cert={alert.get('cert_score', 0):.3f}  graph={alert.get('graph_score', 0):.3f}

Findings:
{findings_text}

Respond with exactly this JSON structure:
{{
  "summary": "<one sentence headline, max 12 words, present tense>",
  "explanation": "<2-3 sentence analyst narrative: what signals mean, possible attack stage, confidence>",
  "action": "<single concrete SOC action>",
  "threat_type": "<C2_BEACON|DATA_EXFILTRATION|PORT_SCAN|TLS_ANOMALY|MALWARE_COMMS|LATERAL_MOVEMENT|UNKNOWN>",
  "confidence": "<HIGH|MEDIUM|LOW>"
}}"""


def analyse_alert(alert: dict, retries: int = 2) -> Optional[dict]:
    """
    Run Groq LLM on one alert dict.
    Returns dict with summary/explanation/action/threat_type/confidence, or None.
    """
    global _client

    if alert.get("severity") not in TRIGGER_SEVERITIES:
        return None
    if not is_configured():
        logger.debug("GROQ_API_KEY not set — skipping")
        return None

    model = GROQ_MODEL
    for attempt in range(retries + 1):
        try:
            client = _get_client()
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": _build_prompt(alert)}],
                temperature=0.2,
                max_tokens=512,
            )
            raw = resp.choices[0].message.content.strip()
            # Strip accidental markdown fences
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            result = json.loads(raw.strip())
            result["alert_id"] = alert.get("alert_id", "")
            return result

        except json.JSONDecodeError:
            logger.warning("Groq non-JSON response (attempt %d)", attempt + 1)
            if attempt < retries:
                time.sleep(1)

        except Exception as e:
            err_str  = str(e)
            err_low  = err_str.lower()

            # Model decommissioned — immediately switch, don't retry same model
            if "model_decommissioned" in err_low or "decommissioned" in err_low:
                logger.warning(
                    "Model %s decommissioned — switching to fallback %s", model, GROQ_FALLBACK
                )
                _client = None   # force re-init on next call
                if model != GROQ_FALLBACK:
                    model = GROQ_FALLBACK
                    continue     # retry immediately with fallback
                else:
                    logger.error("Fallback model also decommissioned — giving up")
                    return None

            elif "rate_limit" in err_low and model == GROQ_MODEL:
                logger.warning("Rate limit hit — falling back to %s", GROQ_FALLBACK)
                model = GROQ_FALLBACK
                time.sleep(2)

            elif attempt < retries:
                logger.warning("Groq attempt %d failed: %s", attempt + 1, e)
                time.sleep(1)

            else:
                logger.error("Groq failed after %d attempts: %s", retries + 1, e)
                return None

    return None


def analyse_and_store(alert: dict, db_path: str = "data/spectra.db") -> Optional[dict]:
    """
    Full pipeline:
      1. Run Groq analysis
      2. Write groq_* columns back to SQLite
      3. Patch Supabase row with Groq fields
    """
    result = analyse_alert(alert)
    if not result:
        return None

    _store_in_sqlite(alert["alert_id"], result, db_path)

    try:
        from src.integrations.supabase_client import patch_groq_fields
        patch_groq_fields(alert["alert_id"], result)
    except Exception as e:
        logger.debug("Supabase groq patch skipped: %s", e)

    return result


def _store_in_sqlite(alert_id: str, groq_data: dict, db_path: str) -> None:
    """Write Groq results back to the alerts row."""
    try:
        from init_db import init_db
        init_db(db_path)
    except Exception as e:
        logger.debug("init_db skipped in groq store: %s", e)

    try:
        conn = sqlite3.connect(db_path, timeout=10)
        existing = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        for col in ("groq_summary", "groq_explanation", "groq_action",
                    "groq_threat_type", "groq_confidence"):
            if col not in existing:
                try:
                    conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    pass

        conn.execute("""
            UPDATE alerts SET
                groq_summary=?, groq_explanation=?, groq_action=?,
                groq_threat_type=?, groq_confidence=?
            WHERE alert_id=?""",
            (
                groq_data.get("summary", ""),
                groq_data.get("explanation", ""),
                groq_data.get("action", ""),
                groq_data.get("threat_type", "UNKNOWN"),
                groq_data.get("confidence", "LOW"),
                alert_id,
            ),
        )
        conn.commit()
        conn.close()
        logger.info("Groq results stored for alert %s", alert_id)
    except Exception as e:
        logger.error("groq _store_in_sqlite failed for %s: %s", alert_id, e)


def batch_analyse_unprocessed(
    db_path: str = "data/spectra.db", limit: int = 20, delay: float = 0.5
) -> int:
    """
    Backfill: analyse HIGH/CRITICAL alerts that have no Groq summary yet.
    Run manually:
        python -c "from src.integrations.groq_client import batch_analyse_unprocessed; batch_analyse_unprocessed()"
    """
    if not is_configured():
        print("GROQ_API_KEY not set in .env")
        return 0

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    existing = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    for col in ("groq_summary", "groq_explanation", "groq_action", "groq_threat_type", "groq_confidence"):
        if col not in existing:
            try:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass
    conn.commit()

    rows = conn.execute("""
        SELECT * FROM alerts
        WHERE severity IN ('HIGH','CRITICAL')
          AND (groq_summary IS NULL OR groq_summary = '')
        ORDER BY composite_score DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()

    processed = 0
    for row in rows:
        result = analyse_and_store(dict(row), db_path)
        if result:
            processed += 1
            print(f"  [{processed}] {row['alert_id']} → {result.get('threat_type')} ({result.get('confidence')})")
        time.sleep(delay)

    print(f"Batch complete: {processed}/{len(rows)} analysed")
    return processed


if __name__ == "__main__":
    print(f"Configured: {is_configured()}")
    if is_configured():
        batch_analyse_unprocessed(limit=5)