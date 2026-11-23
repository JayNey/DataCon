BEGIN;

-- Serialize concurrent migration runs, matching 005-011. The trigger is
-- replaced idempotently below, so existing databases can re-apply this file.
SELECT pg_advisory_xact_lock(hashtext('datacon:migrations'));

-- T10 parent demotion guard. 011 protects child writes: every non-null
-- parent_job_id must reference a v2 family. It does not protect the parent
-- row itself, so an UPDATE could downgrade a family that still has children
-- to a v1 row (or to a different job_kind) and leave those children without a
-- valid aggregation parent. This trigger closes that gap.
--
-- The check runs only when one of the identity columns changes. A child INSERT
-- that races the demotion is serialized by 011's ``FOR KEY SHARE`` parent
-- lock: it either observes the family before the demotion commits or fails
-- after the parent stops being a v2 family. This file is additive and does not
-- edit the frozen 010/011 migrations.
CREATE OR REPLACE FUNCTION datacon_jobs_parent_demotion_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.job_contract_version = 2 AND OLD.job_kind = 'family' THEN
        IF NEW.job_contract_version IS DISTINCT FROM 2
           OR NEW.job_kind IS DISTINCT FROM 'family' THEN
            IF EXISTS (
                SELECT 1 FROM jobs WHERE parent_job_id = OLD.job_id
            ) THEN
                RAISE EXCEPTION 'jobs_family_parent_demotion_with_live_child'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS jobs_parent_demotion_guard ON jobs;
CREATE TRIGGER jobs_parent_demotion_guard
    BEFORE UPDATE OF job_contract_version, job_kind, family_id ON jobs
    FOR EACH ROW EXECUTE FUNCTION datacon_jobs_parent_demotion_guard();

COMMIT;
