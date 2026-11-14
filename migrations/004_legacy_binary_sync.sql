BEGIN;

-- Legacy T01/T02 binary jobs were archived as BLOCKED before 002 added
-- workflow_synced. They are terminal and must not be picked up by the T03
-- worker (claim_next also excludes this reason code for rows written by an
-- older binary after the migration). Re-running this migration is safe.
UPDATE jobs
SET workflow_synced = true,
    updated_at = clock_timestamp()
WHERE state = 'BLOCKED'
  AND reason_code = 'UNSUPPORTED_TARGET'
  AND workflow_synced = false;

COMMIT;
