BEGIN;

-- Serialize concurrent migration runs, matching 005-012. The trigger is
-- replaced idempotently below, so existing databases can re-apply this file.
SELECT pg_advisory_xact_lock(hashtext('datacon:migrations'));

-- T10 child-insert parent-state guard. Migration 011 proves that a non-null
-- parent_job_id references a v2 family, but it does not prove that the family
-- is still open for aggregation. ``complete_family`` holds the family row lock
-- while it checks for non-terminal children and writes COMPLETED; a concurrent
-- child INSERT waits on 011's ``FOR KEY SHARE`` and, without this guard, would
-- then succeed against the committed COMPLETED family, leaving
-- ``COMPLETED family + PREPARING child`` and a claimable orphan.
--
-- The parent read includes ``state`` and is still taken with ``FOR KEY SHARE``:
-- the INSERT is serialized with the completing transaction, then re-evaluates
-- the latest committed parent row and fails closed instead of inserting under
-- a family that is no longer AGGREGATING. This trigger is the database
-- backstop; the application check in ``complete_family`` is not sufficient on
-- its own because a row lock only serializes the writers.
--
-- 013 is additive: it replaces the trigger function created by 011 and does not
-- edit the frozen 010/011/012 files.
CREATE OR REPLACE FUNCTION datacon_jobs_parent_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_kind text;
    parent_version integer;
    parent_state text;
BEGIN
    IF NEW.parent_job_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT job_kind, job_contract_version, state
      INTO parent_kind, parent_version, parent_state
      FROM jobs
     WHERE job_id = NEW.parent_job_id
       FOR KEY SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'jobs_parent_job_id_must_reference_v2_family'
            USING ERRCODE = '23514';
    END IF;

    IF parent_version IS DISTINCT FROM 2
       OR parent_kind IS DISTINCT FROM 'family' THEN
        RAISE EXCEPTION 'jobs_parent_job_id_must_reference_v2_family'
            USING ERRCODE = '23514';
    END IF;

    IF parent_state IS DISTINCT FROM 'AGGREGATING' THEN
        RAISE EXCEPTION 'jobs_parent_job_id_must_be_aggregating_family'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS jobs_parent_guard ON jobs;
CREATE TRIGGER jobs_parent_guard
    BEFORE INSERT OR UPDATE OF parent_job_id ON jobs
    FOR EACH ROW EXECUTE FUNCTION datacon_jobs_parent_guard();

COMMIT;
