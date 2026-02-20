ALTER TABLE scans ADD COLUMN lease_owner TEXT;
ALTER TABLE scans ADD COLUMN lease_expires_at INTEGER;
ALTER TABLE scans ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN next_attempt_at INTEGER;
ALTER TABLE scans ADD COLUMN started_at INTEGER;
ALTER TABLE scans ADD COLUMN completed_at INTEGER;

CREATE INDEX IF NOT EXISTS idx_scans_queue_claim
ON scans (status, lease_expires_at, next_attempt_at, created_at);
