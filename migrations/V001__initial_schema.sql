PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Categorías extraídas de Reglas.csv (col1 agrupadora)
CREATE TABLE IF NOT EXISTS rule_categories (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    sort_order  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    id           TEXT PRIMARY KEY,
    raw_id       TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('ERROR','WARNING','INFO')) DEFAULT 'WARNING',
    category_id  TEXT REFERENCES rule_categories(id) ON DELETE SET NULL,
    enabled      BOOLEAN NOT NULL DEFAULT 1,
    is_abstract  BOOLEAN NOT NULL DEFAULT 0,
    triggers     TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS app_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    value_type  TEXT NOT NULL CHECK (value_type IN ('string','integer','float','boolean','json')) DEFAULT 'string',
    description TEXT,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS audit_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path       TEXT NOT NULL,
    file_name       TEXT NOT NULL,
    file_hash       TEXT,
    file_size_bytes INTEGER,
    triggered_by    TEXT,
    total_findings  INTEGER NOT NULL DEFAULT 0,
    errors          INTEGER NOT NULL DEFAULT 0,
    warnings        INTEGER NOT NULL DEFAULT 0,
    info            INTEGER NOT NULL DEFAULT 0,
    qg_passed       BOOLEAN,
    qg_threshold_pct REAL,
    duration_ms     INTEGER,
    pdf_path        TEXT,
    engine_version  TEXT,
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    finished_at     TEXT
);

CREATE TABLE IF NOT EXISTS audit_issues (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_run_id INTEGER NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    rule_id      TEXT NOT NULL,
    severity     TEXT NOT NULL,
    line_number  INTEGER NOT NULL,
    line_content TEXT NOT NULL,
    description  TEXT NOT NULL,
    file_path    TEXT NOT NULL
);

CREATE VIEW IF NOT EXISTS v_audit_summary AS
    SELECT
        r.id,
        r.name,
        r.enabled,
        (SELECT COUNT(*) FROM audit_issues ai WHERE ai.rule_id = r.id) AS times_triggered
    FROM rules r
    WHERE r.is_abstract = 0
    ORDER BY r.raw_id;

CREATE TRIGGER IF NOT EXISTS trg_rules_updated_at
AFTER UPDATE ON rules
BEGIN
    UPDATE rules SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_app_settings_updated_at
AFTER UPDATE ON app_settings
BEGIN
    UPDATE app_settings SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE key = NEW.key;
END;
