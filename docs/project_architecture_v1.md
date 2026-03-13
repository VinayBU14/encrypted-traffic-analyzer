# Encrypted Traffic Analyzer: Project Architecture V1

## Status

This document freezes the version 1 architecture for the encrypted traffic analyzer project.
It defines the project goal, pipeline stages, V1 feature schema, module responsibilities,
data contracts, technology assumptions, and known risks.

V1 is designed as a hackathon-friendly, research-style prototype:

- simple enough to implement quickly
- modular enough to remain maintainable
- credible enough to demonstrate encrypted-traffic threat detection without payload decryption

## 1. Project Overview

### 1.1 Project Goal

Detect malicious or suspicious activity inside encrypted network traffic without decrypting payloads.

### 1.2 Problem Statement

Traditional network inspection often relies on payload visibility. In encrypted traffic, the payload is not available for inspection, which makes signature-based content analysis ineffective. The system therefore must detect threats by learning and scoring observable communication behavior rather than packet contents.

### 1.3 Detection Strategy

V1 detection is based on the following observable signals:

- packet and flow metadata
- traffic timing and packet-size behavior
- TCP session behavior
- TLS handshake metadata
- certificate metadata when visible
- optional JA3 and JA3S fingerprints as enrichment
- lightweight relationship mapping between device, IP, domain, certificate, and alert entities

The primary V1 machine learning unit is the network flow, not the individual packet.

### 1.4 Capture Mode

V1 capture mode is offline-first.

- Primary mode: replayed PCAP ingestion
- Secondary training source: labeled flow CSV datasets such as CIC-IDS2017 for rapid baseline experiments
- Deferred mode: live interface sniffing after feature parity is established

### 1.5 Learning Mode

V1 uses supervised learning as the primary detection mode.

- Initial task: binary classification, benign vs suspicious
- Offline experiments may keep multiclass labels for analysis, but the demo pipeline exposes binary alerting
- Anomaly detection is explicitly out of scope for V1 implementation, though the overall architecture can support it later

### 1.6 Threat Intelligence Depth

Threat intelligence in V1 is lightweight enrichment, not a separate graph-analytics subsystem.

- Correlate alerts by shared IP, domain, certificate, device, JA3, or JA3S where available
- Use relationship mapping for explanation and dashboard pivots
- Defer deep infrastructure clustering and graph algorithms to later versions

### 1.7 System Architecture

The top-level architecture remains:

Dataset or Network Traffic
-> Packet Capture or Loader
-> Metadata Extraction
-> Feature Engineering
-> ML Model Training
-> Trained Detection Model
-> Detection Engine
-> API
-> Dashboard Visualization

### 1.8 V1 Workflow Summary

1. Load PCAP traffic or labeled dataset flows.
2. Parse packets and group them into flows.
3. Extract observable metadata from packet headers and TLS handshakes.
4. Convert metadata into flow-level statistical and TLS-derived features.
5. Train a supervised model on labeled feature rows.
6. Serialize the trained model together with preprocessing assumptions.
7. Apply the same extraction and feature engineering logic to new traffic.
8. Score each flow and convert scores into alerts.
9. Expose alerts and summaries through an API and dashboard.

### 1.9 Planned Technology Stack

- Language: Python
- Packet and traffic parsing: Scapy or an equivalent PCAP parser with TLS parsing support
- Data processing: pandas, numpy
- Machine learning: scikit-learn
- Initial baseline model: Random Forest or Gradient Boosting from scikit-learn
- Model artifact storage: joblib
- API layer: FastAPI
- Dashboard: Streamlit
- Development environment: VS Code

### 1.10 Intended Repository Structure

The planned repository structure for V1 is:

```text
encrypted-traffic-analyzer/
  docs/
    project_architecture_v1.md
    threat_model.md
    dataset_notes.md
    experiment_results.md

  data/
    raw/
    processed/
    features/

  notebooks/

  src/
    packet_capture/
    metadata_extraction/
    feature_engineering/
    ml_models/
    detection_engine/
    api/
    dashboard/
    utils/

  models/

  configs/

  scripts/

  tests/
```

## 2. End-to-End Pipeline

### 2.1 Dataset or PCAP Input

The pipeline begins with one of two traffic sources:

- PCAP files containing packet-level traffic
- precomputed labeled flow CSV files used for rapid supervised baselines

PCAP input is the richer source because it preserves timestamps, transport headers, and TLS handshake data. CSV flow datasets are useful for fast modeling but may not include JA3, certificate details, or full TLS handshake fields.

### 2.2 Packet Capture or Loader

This stage ingests raw traffic.

- For PCAP input, it reads packet records in capture order.
- For live traffic, which is deferred in V1, it would read packets from a network interface.
- For labeled flow CSVs, it bypasses packet parsing and enters the pipeline at the feature dataset layer for training experiments.

Output:

- normalized packet records for PCAP-based paths
- feature dataset rows for CSV-based training-only paths

### 2.3 Metadata Extraction

This stage parses each packet and extracts observable information that remains visible even when payloads are encrypted.

It performs the following tasks:

- parse IP and transport-layer headers
- identify the flow for each packet using the 5-tuple and timing context
- maintain forward and backward packet accounting
- extract packet timestamps, sizes, flags, and directional totals
- parse TLS handshake messages when present
- capture TLS version, cipher details, extensions, SNI presence, and certificate metadata when visible
- optionally derive JA3 and JA3S if the parser supports stable extraction

Output:

- packet metadata records
- flow state records containing accumulated metadata and TLS observations

### 2.4 Feature Engineering

This stage transforms per-packet and per-flow metadata into model-ready feature rows.

It performs the following tasks:

- finalize flow boundaries using connection teardown or timeout rules
- aggregate packet counts and byte counts by direction
- compute duration, rates, inter-arrival statistics, and packet-size statistics
- compute TCP flag counts and basic session behavior statistics
- derive TLS summary features from handshake observations
- separate prediction metadata from actual ML feature columns

Output:

- one feature row per completed flow
- optional label column during training
- retained context fields for explainability and dashboard display

### 2.5 ML Model Training

This stage learns a mapping from engineered features to labels.

It performs the following tasks:

- load feature rows and labels
- select the frozen V1 feature schema
- perform preprocessing such as missing-value handling and encoding decisions
- split data for evaluation with leakage-aware strategy when possible
- train a supervised classifier
- evaluate the model using classification metrics

Output:

- trained model artifact
- preprocessing metadata
- feature list and schema version
- evaluation summary and threshold recommendation

### 2.6 Trained Model Artifact

The trained artifact is not only the classifier. It is the complete inference bundle.

It should conceptually contain:

- trained model weights
- ordered feature list
- preprocessing assumptions
- label mapping
- threshold or decision rule
- model metadata such as training dataset and schema version

### 2.7 Detection Engine

This stage applies the training-time logic to new traffic.

It performs the following tasks:

- ingest packet streams or replayed PCAPs
- build and update active flow state
- run the same metadata extraction logic as training
- run the same feature engineering logic as training
- load the trained model bundle
- score each completed flow
- convert model output into alert objects
- attach lightweight entity relationships for explanation

Output:

- predictions and risk scores per flow
- alert objects for suspicious flows
- entity relationships used by the API and dashboard

### 2.8 API

The API exposes detection results to external consumers.

It provides:

- alert retrieval
- flow prediction summaries
- entity pivot views such as by destination IP, domain, certificate, or JA3
- basic health and run metadata

Output:

- JSON responses for the dashboard or other clients

### 2.9 Dashboard

The dashboard is the presentation layer.

It visualizes:

- suspicious flows
- risk scores and labels
- top suspicious endpoints or entities
- traffic trends over time
- simple pivots across IP, domain, certificate, and fingerprint relationships

Its purpose in V1 is explanation and demo clarity, not full SOC functionality.

## 3. V1 Feature Schema

### 3.1 Scope of the V1 Schema

The V1 model must use a realistic feature set that is:

- extractable from PCAP traffic without decrypting payloads
- mostly numeric or boolean for simple classical models
- stable across training and inference
- useful for encrypted-traffic behavior analysis

V1 separates fields into three categories:

- context fields: retained for tracking and visualization, not used directly as model inputs
- model feature fields: the exact columns used by the classifier
- enrichment fields: optional metadata for investigation and dashboard pivots

### 3.2 Context Fields

These fields identify the flow and support traceability. They are not primary ML input features in V1.

- flow_id
- src_ip
- dst_ip
- src_port
- dst_port
- protocol
- flow_start_ts
- flow_end_ts
- source_type
- source_file
- label (training only)

### 3.3 Exact V1 Model Feature Columns

#### A. Core flow and packet metadata features

These features are realistic to extract from PCAPs and are the main V1 model inputs.

1. duration_ms
2. total_packets
3. total_bytes
4. fwd_packets
5. bwd_packets
6. fwd_bytes
7. bwd_bytes
8. packet_rate_per_sec
9. byte_rate_per_sec
10. avg_packet_size
11. min_packet_size
12. max_packet_size
13. std_packet_size
14. mean_iat_ms
15. min_iat_ms
16. max_iat_ms
17. std_iat_ms
18. fwd_mean_iat_ms
19. bwd_mean_iat_ms
20. syn_count
21. ack_count
22. fin_count
23. rst_count
24. psh_count
25. active_time_ms
26. idle_time_ms

#### B. TLS-derived model features

These are included only when TLS metadata is visible in the PCAP. Missing values are allowed and must be handled consistently.

27. tls_seen
28. tls_version_code
29. tls_cipher_suite_count
30. tls_extension_count
31. tls_sni_present
32. tls_alpn_present
33. tls_cert_present
34. tls_cert_validity_days
35. tls_cert_self_signed
36. tls_cert_san_count

### 3.4 Enrichment-Only Fields for V1

These fields are useful for analysis and dashboard pivots but are not part of the exact baseline ML feature vector in V1.

- tls_sni_value
- tls_ja3
- tls_ja3s
- tls_selected_cipher
- tls_issuer_common_name
- tls_subject_common_name
- tls_serial_number
- tls_certificate_fingerprint
- dns_query_name when visible outside encrypted DNS
- device_id if an external mapping is available

### 3.5 Feature Origins

#### Features originating from packet metadata

- duration_ms
- total_packets
- total_bytes
- fwd_packets
- bwd_packets
- fwd_bytes
- bwd_bytes
- packet_rate_per_sec
- byte_rate_per_sec
- avg_packet_size
- min_packet_size
- max_packet_size
- std_packet_size
- mean_iat_ms
- min_iat_ms
- max_iat_ms
- std_iat_ms
- fwd_mean_iat_ms
- bwd_mean_iat_ms
- syn_count
- ack_count
- fin_count
- rst_count
- psh_count
- active_time_ms
- idle_time_ms

#### Features originating from TLS handshake information

- tls_seen
- tls_version_code
- tls_cipher_suite_count
- tls_extension_count
- tls_sni_present
- tls_alpn_present
- tls_cert_present
- tls_cert_validity_days
- tls_cert_self_signed
- tls_cert_san_count

### 3.6 Realistic Extraction Expectations from PCAPs

Realistically extractable from PCAPs in V1:

- timestamps
- packet sizes
- transport protocol and ports
- TCP flags
- flow directionality
- flow duration and rates
- TLS ClientHello and ServerHello summary fields when present
- certificate summary metadata when the handshake is captured
- JA3 and JA3S if a stable parser path is available

Not guaranteed to be available for every flow:

- SNI
- ALPN
- certificate chain details
- JA3 and JA3S
- DNS names

Reasons include missing handshake packets, resumed sessions, non-TLS protocols, partial captures, and parser limitations.

## 4. Data Contract Between Modules

### 4.1 packet_capture -> metadata_extraction

#### Input to packet_capture

- PCAP file path or live capture configuration
- capture filters and runtime settings

#### Output from packet_capture

Normalized packet records with at least:

- timestamp
- raw packet length
- network protocol
- source and destination IP
- source and destination port when applicable
- TCP flags when applicable
- raw packet bytes or parsed packet object reference

### 4.2 metadata_extraction -> feature_engineering

#### Input to metadata_extraction

- normalized packet records

#### Output from metadata_extraction

Flow metadata records with at least:

- flow_id
- 5-tuple identity
- start and end timestamps
- packet counts and byte counts by direction
- packet size history or packet size aggregates
- inter-arrival timing observations
- TCP flag counters
- TLS summary fields when observed
- certificate summary fields when observed
- optional enrichment values such as JA3 and JA3S

### 4.3 feature_engineering -> ml_model

#### Input to feature_engineering

- completed or timed-out flow metadata records

#### Output from feature_engineering

Model-ready feature rows containing:

- context fields
- exact ordered V1 model feature columns
- optional label for supervised training
- schema version

### 4.4 ml_model -> detection_engine

#### Input to ml_model training

- feature matrix X
- labels y
- training configuration

#### Output from ml_model training

Model bundle containing:

- trained classifier
- feature column order
- preprocessing metadata
- label mapping
- threshold configuration
- schema version

### 4.5 detection_engine -> API

#### Input to detection_engine

- packet stream or replayed PCAP
- model bundle
- detection configuration

#### Output from detection_engine

Prediction and alert records containing:

- flow_id
- flow context fields
- predicted_label
- predicted_score
- alert_severity
- top supporting metadata fields
- linked entities such as IP, domain, certificate fingerprint, JA3, or JA3S where available
- processing timestamp

### 4.6 API -> dashboard

#### Input to API

- prediction and alert records
- summary aggregations

#### Output from API

- JSON payloads for flows, alerts, entity summaries, and trends

#### Input to dashboard

- API JSON responses

#### Output from dashboard

- rendered visual views for analysts or demo users

## 5. Module Responsibilities

### packet_capture

- read PCAP traffic in deterministic order
- optionally support live capture later
- emit normalized packet records

### metadata_extraction

- parse headers and TLS handshake data
- assemble flow state
- maintain directional counters and timing observations

### feature_engineering

- compute the frozen V1 feature schema
- separate context fields from model inputs
- handle missing TLS-derived values consistently

### ml_models

- train baseline classifier
- evaluate model performance
- save and load the model bundle

### detection_engine

- apply the training-time feature logic to unseen traffic
- score flows and generate alerts
- enrich alerts with lightweight entity relationships

### api

- serve detection outputs and summaries
- provide stable endpoints for the dashboard

### dashboard

- display alerts, entities, and simple traffic patterns
- support clear demo storytelling and operator interpretation

### utils

- shared helpers for config loading, serialization, parsing utilities, and schema validation

## 6. Technology Stack and Operational Choices

### 6.1 Frozen V1 Choices

- Architecture style: pipeline-based, flow-centric
- Primary traffic mode: offline PCAP replay
- Model task: supervised binary classification
- Detection target: suspicious encrypted traffic at flow level
- Enrichment depth: lightweight relationship mapping only
- API style: FastAPI JSON service
- UI style: Streamlit dashboard

### 6.2 Deferred or Optional Items

- live capture mode
- anomaly detection mode
- graph analytics and infrastructure clustering
- QUIC and HTTP/3 support
- broad UDP protocol support
- deep certificate-chain analytics

## 7. Design Assumptions

- encrypted payloads are not inspected or decrypted
- enough packet metadata is available to build stable flows
- TLS handshake packets are available for at least some flows
- the same feature schema will be used for training and inference
- public datasets may be used for baseline model development, but richer TLS features require PCAP-based extraction
- V1 prioritizes reproducibility and demo clarity over real-time scale

## 8. Risks and Technical Caveats

### 8.1 Dataset Risks

- public benchmark datasets may not reflect modern production traffic
- labels may be tied to specific capture conditions or hosts
- random train-test splits can leak environmental information

### 8.2 Feature Risks

- some TLS features will be missing for many flows
- JA3 and JA3S may require parser-specific work
- certificate fields may be absent in resumed or partial sessions

### 8.3 Pipeline Risks

- train-serving skew if feature generation differs between training and inference
- unstable flow timeout rules can change feature values
- packet loss or truncated PCAPs can distort feature calculations

### 8.4 Model Risks

- class imbalance may bias the classifier toward benign predictions
- binary detection may hide attack-family-specific behavior
- classical models may overfit dataset-specific quirks if validation is weak

## 9. Improvements That Preserve the Agreed Architecture

The following improvements are recommended without changing the core V1 design:

- enforce one canonical schema definition shared by training and detection
- keep model inputs numeric and boolean in V1 for stable baseline training
- treat JA3, JA3S, SNI, and certificate identifiers as enrichment first and model inputs later if category handling is justified
- prefer capture-based, host-based, or time-based validation over naive random row splits
- keep the dashboard narrow and explanatory rather than broad and operationally complex

## 10. V1 Freeze Summary

V1 is now defined as a flow-centric encrypted-traffic detection prototype that:

- works primarily from replayed PCAP traffic
- uses packet metadata and selective TLS handshake features
- trains one supervised binary classifier
- applies the same feature schema in training and detection
- produces scored alerts and lightweight entity correlations
- exposes results through a FastAPI backend and Streamlit dashboard

This document is the source of truth for V1 architecture decisions before implementation begins.