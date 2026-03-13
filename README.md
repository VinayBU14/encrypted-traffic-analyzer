# encrypted-traffic-analyzer

AI-based detection of malicious activity in encrypted network traffic — without decrypting payloads.

## Overview

This project detects malicious or suspicious activity in encrypted network traffic using observable
communication behavior: packet metadata, flow statistics, TCP session behavior, and TLS handshake
metadata. It does **not** inspect or decrypt encrypted payloads.

## Architecture

See [docs/project_architecture_v1.md](docs/project_architecture_v1.md) for the full V1 architecture.

### Pipeline Summary

```
Dataset or Network Traffic
  -> Packet Capture / Loader
  -> Metadata Extraction
  -> Feature Engineering
  -> ML Model Training  ->  Trained Detection Model
  -> Detection Engine
  -> API
  -> Dashboard Visualization
```

### Technology Stack

| Component       | Technology                      |
|-----------------|---------------------------------|
| Language        | Python                          |
| Packet parsing  | Scapy                           |
| Data processing | pandas, numpy                   |
| ML              | scikit-learn (Random Forest / Gradient Boosting) |
| Model storage   | joblib                          |
| API             | FastAPI                         |
| Dashboard       | Streamlit                       |
| Config          | PyYAML                          |

## Repository Structure

```
encrypted-traffic-analyzer/
  docs/                        # Architecture, threat model, dataset notes, experiment results
  data/
    raw/                       # Raw PCAP files and source datasets
    processed/                 # Parsed and normalized intermediate data
    features/                  # Engineered feature rows ready for training
  notebooks/                   # Exploratory analysis notebooks
  src/
    packet_capture/            # PCAP ingestion and packet normalization
    metadata_extraction/       # Header parsing, flow assembly, TLS handshake extraction
    feature_engineering/       # V1 feature schema computation
    ml_models/                 # Model training, evaluation, and artifact management
    detection_engine/          # Inference pipeline and alert generation
    api/                       # FastAPI service
    dashboard/                 # Streamlit dashboard
    utils/                     # Shared helpers
  models/                      # Serialized model artifacts
  configs/                     # Runtime configuration
  scripts/                     # Utility scripts
  tests/                       # Unit and integration tests
```

## Getting Started

Install dependencies:

```bash
pip install -r requirements.txt
```

## Documentation

- [Project Architecture V1](docs/project_architecture_v1.md)
- [Threat Model](docs/threat_model.md)
- [Dataset Notes](docs/dataset_notes.md)
- [Experiment Results](docs/experiment_results.md)

## License

See [LICENSE](LICENSE).
