BEGIN;

-- Incremental workflow records for T03/T04. Existing T01/T02 jobs and the
-- 001 index/columns are preserved; every statement is re-runnable.
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS operator_id text;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS stage text;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS state_version bigint NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS generation bigint NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS lease_owner text;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS prepare_deadline_at timestamptz;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS review_deadline_at timestamptz;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS execute_deadline_at timestamptz;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS approved_at timestamptz;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS last_error text;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS workflow_synced boolean NOT NULL DEFAULT false;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP;

CREATE TABLE IF NOT EXISTS plans (
    plan_id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    plan_digest text NOT NULL,
    plan jsonb NOT NULL,
    summary jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT plans_job_unique UNIQUE (job_id),
    CONSTRAINT plans_digest_format CHECK (plan_digest ~ '^sha256:[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS reviews (
    review_id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    plan_digest text NOT NULL,
    reviewer_id text NOT NULL,
    decision text NOT NULL,
    review_deadline_at timestamptz NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT reviews_job_unique UNIQUE (job_id),
    CONSTRAINT reviews_decision CHECK (decision IN ('approve', 'reject')),
    CONSTRAINT reviews_digest_format CHECK (plan_digest ~ '^sha256:[0-9a-f]{64}$')
);

ALTER TABLE reviews ADD COLUMN IF NOT EXISTS review_deadline_at timestamptz;

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    stage text NOT NULL,
    step_key text NOT NULL,
    attempt_no integer NOT NULL,
    generation bigint NOT NULL,
    container_id text,
    input_digest text,
    status text NOT NULL,
    result jsonb,
    started_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at timestamptz,
    CONSTRAINT attempts_step_unique UNIQUE (job_id, stage, step_key, attempt_no)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id bigserial PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    stage text,
    attempt_no integer,
    event_type text NOT NULL,
    reason_code text,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS jobs_claim_idx
    ON jobs (state, workflow_synced, submitted_at);
CREATE INDEX IF NOT EXISTS jobs_review_deadline_idx
    ON jobs (review_deadline_at) WHERE state = 'AWAITING_REVIEW';
CREATE INDEX IF NOT EXISTS reviews_job_idx ON reviews (job_id);
CREATE INDEX IF NOT EXISTS attempts_job_idx ON attempts (job_id, stage, step_key);
CREATE INDEX IF NOT EXISTS audit_events_job_idx ON audit_events (job_id, created_at);

COMMIT;
