BEGIN;

-- Serialize concurrent migration runs, matching the earlier migrations.
SELECT pg_advisory_xact_lock(hashtext('datacon:migrations'));

-- A terminal row is either archived with both a path and a manifest digest,
-- or it has no current evidence at all. Older rows could contain a stale
-- verdict/pointer next to evidence_status='failed' (or an archived row with
-- NULL pointer columns), so repair them before adding the constraint.
UPDATE jobs
SET verdict = NULL,
    verdict_reason = NULL,
    evidence_path = NULL,
    evidence_digest = NULL,
    evidence_status = 'failed'
WHERE evidence_status IS DISTINCT FROM 'archived'
  AND (
      verdict IS NOT NULL
      OR verdict_reason IS NOT NULL
      OR evidence_path IS NOT NULL
      OR evidence_digest IS NOT NULL
  );

UPDATE jobs
SET verdict = NULL,
    verdict_reason = NULL,
    evidence_path = NULL,
    evidence_digest = NULL,
    evidence_status = 'failed'
WHERE evidence_status = 'archived'
  AND (evidence_path IS NULL OR evidence_digest IS NULL);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'jobs'::regclass
          AND conname = 'jobs_archived_evidence_check'
    ) THEN
        ALTER TABLE jobs ADD CONSTRAINT jobs_archived_evidence_check
            CHECK (
                COALESCE(evidence_status = 'archived', false)
                = (evidence_path IS NOT NULL AND evidence_digest IS NOT NULL)
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'jobs'::regclass
          AND conname = 'jobs_failed_evidence_no_verdict_check'
    ) THEN
        ALTER TABLE jobs ADD CONSTRAINT jobs_failed_evidence_no_verdict_check
            CHECK (NOT (evidence_status = 'failed' AND verdict IS NOT NULL));
    END IF;
END $$;

COMMIT;
