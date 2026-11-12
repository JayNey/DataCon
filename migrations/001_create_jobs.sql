BEGIN;

CREATE TABLE IF NOT EXISTS jobs (
    job_id uuid PRIMARY KEY,
    request jsonb NOT NULL,
    state text NOT NULL DEFAULT 'QUEUED',
    reason_code text,
    submitted_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- This migration is documented as re-runnable. The ADD COLUMN also upgrades a
-- jobs table created by the previous revision, which had no reason_code.
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS reason_code text;

CREATE INDEX IF NOT EXISTS jobs_queue_idx ON jobs (state, submitted_at);

COMMIT;
