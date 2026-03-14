# Spectra: Encrypted Traffic Analyzer (Planning Blueprint)

## 1) Project Aim

Spectra detects suspicious activity in encrypted TLS traffic **without decrypting payloads**.  
The system prioritizes deterministic, explainable security scoring over black-box classification.

## 2) Core Detection Philosophy

- Primary detection = **multi-signal weighted scoring**
- Secondary safety net = **Isolation Forest anomaly signal**
- Not a supervised benign/malicious classifier in the core path

## 3) End-to-End Workflow

1. Ingest PCAP traffic.
2. Filter TLS traffic only.
3. Reconstruct flows/sessions from 5-tuple + timing.
4. Extract TLS metadata from ClientHello and certificate data.
5. Engineer normalized scoring inputs.
6. Run 4 analysis modules in parallel:
   - JA3 Analysis
   - Certificate Lifecycle Analysis
   - Beacon Detection
   - Infrastructure Graph Analysis
7. Compute weighted composite score.
8. Apply Isolation Forest safety-net uplift when conditions are met.
9. Map score to severity tier.
10. Build structured alert JSON.
11. Serve through FastAPI.
12. Visualize through Streamlit dashboard.

## 4) Primary Scoring Engine

### Parallel Modules and Weights

- Module A: JA3 Analysis = **0.35**
- Module B: Certificate Analysis = **0.20**
- Module C: Beacon Detection = **0.25**
- Module D: Graph Analysis = **0.20**

### Composite Formula

`composite_score = 0.35*ja3 + 0.25*beacon + 0.20*cert + 0.20*graph`

### Severity Output

- CLEAN
- LOW
- MEDIUM
- HIGH
- CRITICAL

## 5) Module Details

### Module A: JA3 Analysis (highest precision signal)

- JA3 hash generation:
  `MD5(TLSVersion, CipherSuites, Extensions, EllipticCurves, ECFormats)`
- 32-char JA3 fingerprint lookup:
  - `data/threat_intel/ja3_malicious.json`
  - `data/threat_intel/ja3_benign.json`
- Scoring:
  - Known malicious -> `0.95`
  - Known benign -> `0.00`
  - Unknown -> `0.10`
- Deterministic lookup, not classifier behavior.

### Module B: Certificate Lifecycle Analysis

Aggregates independent certificate-risk findings into `cert_score` (clamped 0..1), with findings text:

- cert age < 7 days -> +0.25 (very young)
- cert age < 30 days -> +0.15 (young, only if NOT already < 7 days; mutually exclusive tier via `elif`)
- self-signed -> +0.35
- Let's Encrypt + young domain -> +0.20
- high SAN count + new SAN domains -> +0.25
- fingerprint in bad DB -> +0.40

### Module C: Beacon Detection

Evaluates repeated `src_ip -> dst_ip` communication patterns (minimum 5 flows):

- `regularity_score`
- `jitter_tightness`
- `payload_consistency`
- `time_independence`

Formula:
`beacon_score = 0.40*regularity + 0.25*jitter + 0.20*payload + 0.15*time`

### Module D: Infrastructure Graph Analysis

Directed graph built with NetworkX:

- Nodes: Device, Domain, IP, Certificate, ASN
- Edges: contacted, resolves_to, uses, covers

Session graph queries:

1. Certificate fanout (domains sharing cert)
2. Destination IP threat-intel presence
3. Multi-device convergence on same destination
4. Malicious-neighbor proximity

Outputs `graph_score` + findings.

## 6) Isolation Forest (Safety Net, Not Primary)

- Model: `sklearn.ensemble.IsolationForest`
- Type: unsupervised anomaly detection
- Trained on clean baseline traffic
- Behavioral features only:
  - regularity_score
  - payload_consistency
  - cert_age_normalized
  - tls_version_encoded
  - bytes_per_second
  - packet_rate
- Output: `anomaly_score` in [0,1]

Integration rule:

```text
IF anomaly_score > 0.7 AND composite_score < 0.5:
    composite_score = max(composite_score, anomaly_score * 0.6)
```

## 7) Technology Stack

- Python
- FastAPI (backend)
- Streamlit (dashboard)
- NetworkX (graph analysis)
- scikit-learn IsolationForest (anomaly safety net)
- YAML configs for runtime constants and thresholds

## 8) Data and Threat Intel Assets

- PCAP inputs: `data/raw/pcap/`
- Processed artifacts: `data/processed/`
- Threat intel:
  - JA3 malicious/benign databases
  - IP reputation feed
- Demo assets: `data/demo/`

## 9) Architectural Rules (Project-Wide)

1. No hardcoded values; pull constants from `configs/default.yaml`.
2. No `print`; use Python logging.
3. One responsibility per file.
4. Type hints on every function signature.
5. Docstrings on every class/public function.
6. Database access only in `src/storage/repositories/`.
7. Dashboard communicates through FastAPI only.
8. `feature_validator.py` must run at training and inference; schema drift is a hard error.

## 10) Repository Structure

This scaffold uses the `spectra/` structure requested for implementation planning and phased build-out.

