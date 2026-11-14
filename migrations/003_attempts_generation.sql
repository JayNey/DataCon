BEGIN;

-- Upgrade databases that already applied the first revision of 002, whose
-- attempts key omitted generation. The table and its rows are preserved; only
-- the uniqueness constraint is replaced. Re-running this migration is safe.
DO $$
BEGIN
    IF to_regclass('attempts') IS NOT NULL THEN
        ALTER TABLE attempts DROP CONSTRAINT IF EXISTS attempts_step_unique;
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('attempts') IS NOT NULL THEN
        ALTER TABLE attempts
            ADD CONSTRAINT attempts_step_unique
            UNIQUE (job_id, stage, step_key, attempt_no, generation);
    END IF;
END $$;

COMMIT;
