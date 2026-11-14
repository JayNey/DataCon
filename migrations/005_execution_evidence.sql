BEGIN;

-- T05/T06 incremental records. Existing jobs, plans, reviews and attempts are
-- preserved; every statement is re-runnable. The verdict and evidence columns
-- are terminal metadata, while execution attempts continue to use the
-- generation-scoped attempts table introduced in 002/003.
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS verdict text;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS verdict_reason text;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS evidence_digest text;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS evidence_path text;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS evidence_status text;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS evidence_error text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid = 'jobs'::regclass AND conname = 'jobs_verdict_check'
    ) THEN
        ALTER TABLE jobs ADD CONSTRAINT jobs_verdict_check
            CHECK (verdict IS NULL OR verdict IN
                   ('REPRODUCED', 'NOT_REPRODUCED', 'INCONCLUSIVE'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid = 'jobs'::regclass AND conname = 'jobs_evidence_status_check'
    ) THEN
        ALTER TABLE jobs ADD CONSTRAINT jobs_evidence_status_check
            CHECK (evidence_status IS NULL OR evidence_status IN
                   ('archived', 'failed'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid = 'jobs'::regclass AND conname = 'jobs_evidence_digest_check'
    ) THEN
        ALTER TABLE jobs ADD CONSTRAINT jobs_evidence_digest_check
            CHECK (evidence_digest IS NULL OR
                   evidence_digest ~ '^sha256:[0-9a-f]{64}$');
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS jobs_execution_claim_idx
    ON jobs (state, lease_expires_at)
    WHERE state IN ('RUNNING', 'ARCHIVING');

COMMIT;
