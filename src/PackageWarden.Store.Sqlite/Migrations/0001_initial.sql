CREATE TABLE IF NOT EXISTS requests (
    id                   TEXT PRIMARY KEY,
    timestamp            TEXT NOT NULL,
    ecosystem            TEXT NOT NULL,
    package              TEXT NOT NULL,
    version              TEXT,
    upstream             TEXT NOT NULL,
    client_ip            TEXT NOT NULL,
    blocked              INTEGER NOT NULL,
    block_mode           TEXT,
    block_reason         TEXT,
    matched_count        INTEGER,
    threshold            INTEGER,
    risk_score           REAL,
    risk_score_threshold REAL,
    duration_ms          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    request_id      TEXT NOT NULL REFERENCES requests(id),
    finding_type    TEXT NOT NULL,
    finding_id      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    cvss_score      REAL,
    score           REAL NOT NULL,
    reported_by     TEXT NOT NULL,
    data            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_requests_timestamp  ON requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_requests_ecosystem  ON requests(ecosystem);
CREATE INDEX IF NOT EXISTS idx_requests_blocked    ON requests(blocked);
CREATE INDEX IF NOT EXISTS idx_requests_package    ON requests(package);
CREATE INDEX IF NOT EXISTS idx_findings_request    ON findings(request_id);
CREATE INDEX IF NOT EXISTS idx_findings_type       ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_id         ON findings(finding_id);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
