
CREATE TABLE IF NOT EXISTS flows (
  flow_id TEXT PRIMARY KEY,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  src_port INTEGER NOT NULL,
  dst_port INTEGER NOT NULL,
  protocol TEXT NOT NULL,
  start_time REAL NOT NULL,
  end_time REAL,
  duration_ms REAL,
  packet_count INTEGER DEFAULT 0,
  bytes_total INTEGER DEFAULT 0,
  upload_bytes INTEGER DEFAULT 0,
  download_bytes INTEGER DEFAULT 0,
  packet_sizes TEXT,
  inter_arrival_ms TEXT,
  tcp_flags TEXT,
  status TEXT DEFAULT 'ACTIVE',
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS tls_sessions (
  session_id TEXT PRIMARY KEY,
  flow_id TEXT NOT NULL REFERENCES flows(flow_id),
  sni_domain TEXT,
  ja3_hash TEXT,
  tls_version INTEGER,
  cipher_suites TEXT,
  extensions TEXT,
  elliptic_curves TEXT,
  cert_subject TEXT,
  cert_issuer TEXT,
  cert_not_before REAL,
  cert_not_after REAL,
  cert_fingerprint TEXT,
  cert_san_list TEXT,
  cert_is_self_signed INTEGER DEFAULT 0,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY,
  flow_id TEXT REFERENCES flows(flow_id),
  timestamp REAL NOT NULL,
  severity TEXT NOT NULL,
  composite_score REAL NOT NULL,
  ja3_score REAL,
  beacon_score REAL,
  cert_score REAL,
  graph_score REAL,
  anomaly_score REAL,
  src_ip TEXT NOT NULL,
  dst_domain TEXT,
  dst_ip TEXT,
  findings TEXT,
  recommended_action TEXT,
  is_suppressed INTEGER DEFAULT 0,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_entities (
  entity_id TEXT PRIMARY KEY,
  entity_type TEXT NOT NULL,
  value TEXT NOT NULL,
  risk_score REAL DEFAULT 0.0,
  is_malicious INTEGER DEFAULT 0,
  metadata TEXT,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flows_src_dst ON flows (src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_status ON flows (status);
CREATE INDEX IF NOT EXISTS idx_flows_start_time ON flows (start_time);

CREATE INDEX IF NOT EXISTS idx_tls_sessions_flow_id ON tls_sessions (flow_id);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_ja3_hash ON tls_sessions (ja3_hash);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_sni_domain ON tls_sessions (sni_domain);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip);

CREATE INDEX IF NOT EXISTS idx_graph_entities_type_value ON graph_entities (entity_type, value);
