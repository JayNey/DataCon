BEGIN;

-- Serialize concurrent migration runs, matching 005-011. The trigger is
-- replaced idempotently below, so existing databases can re-apply this file.
SELECT pg_advisory_xact_lock(hashtext('datacon:migrations'));

-- T10 parent identity guard. Migration 010 fixes the v2 identity shapes but a
-- plain FK only proves the parent row exists: it would accept a v1 job, a
-- campaign or a round as ``parent_job_id``. The v0.2 contract requires every
-- non-null parent to be a real ``job_contract_version = 2 AND job_kind =
-- 'family'`` row. A BEFORE INSERT OR UPDATE trigger enforces that at the
-- database boundary, so an application bug cannot create a second aggregation
-- layer. ``FOR KEY SHARE`` keeps a concurrent parent kind/version update from
-- slipping between the check and the child write; it does not block ordinary
-- reads or unrelated columns.
--
-- 011 is additive and does not edit the frozen 010 migration.
CREATE OR REPLACE FUNCTION datacon_jobs_parent_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_kind text;
    parent_version integer;
BEGIN
    IF NEW.parent_job_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT job_kind, job_contract_version
      INTO parent_kind, parent_version
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

    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS jobs_parent_guard ON jobs;
CREATE TRIGGER jobs_parent_guard
    BEFORE INSERT OR UPDATE OF parent_job_id ON jobs
    FOR EACH ROW EXECUTE FUNCTION datacon_jobs_parent_guard();

COMMIT;
