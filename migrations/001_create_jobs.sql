BEGIN;

CREATE TABLE IF NOT EXISTS jobs (
    job_id uuid PRIMARY KEY,
    request jsonb NOT NULL,
    state text NOT NULL DEFAULT 'QUEUED',
    submitted_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS jobs_queue_idx ON jobs (state, submitted_at);

COMMIT;
