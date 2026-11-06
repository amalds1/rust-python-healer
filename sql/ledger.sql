PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS variants (
  id TEXT PRIMARY KEY,
  code_sha256 TEXT NOT NULL,
  config_sha256 TEXT NOT NULL,
  engine TEXT NOT NULL,
  parent_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(code_sha256, config_sha256, engine)
);
CREATE TABLE IF NOT EXISTS evaluations (
  id INTEGER PRIMARY KEY,
  variant_id TEXT NOT NULL REFERENCES variants(id),
  safety TEXT NOT NULL,
  correctness TEXT NOT NULL,
  speed TEXT NOT NULL,
  reliability TEXT NOT NULL,
  compatibility TEXT NOT NULL,
  futureproof TEXT NOT NULL,
  compile TEXT NOT NULL,
  tests TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  log TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_eval_variant ON evaluations(variant_id, id DESC);
