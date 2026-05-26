CREATE TABLE IF NOT EXISTS exceptions (
    id          TEXT PRIMARY KEY,
    ecosystem   TEXT NOT NULL,
    package     TEXT NOT NULL,
    version     TEXT,
    granted_at  TEXT NOT NULL,
    revoked_at  TEXT,
    request_id  TEXT REFERENCES requests(id),
    finding_ids TEXT NOT NULL,
    notes       TEXT
);

CREATE INDEX IF NOT EXISTS idx_exceptions_ecosystem ON exceptions(ecosystem);
CREATE INDEX IF NOT EXISTS idx_exceptions_package   ON exceptions(package);
CREATE INDEX IF NOT EXISTS idx_exceptions_active    ON exceptions(revoked_at);
