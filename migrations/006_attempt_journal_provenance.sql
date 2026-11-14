BEGIN;

SELECT pg_advisory_xact_lock(hashtext('datacon:migrations'));

-- EXE-01: a durable tool journal may only be adopted when it is bound to a
-- database attempt row. The token is written to both the attempts row and the
-- journal; the journal additionally carries an HMAC produced with a key that
-- lives outside DATACON_RUN_ROOT. Existing rows stay valid (NULL token means
-- "never adopt"), and the column is additive and idempotent.
ALTER TABLE attempts ADD COLUMN IF NOT EXISTS attempt_token text;

CREATE INDEX IF NOT EXISTS attempts_step_generation_idx
    ON attempts (job_id, stage, step_key, generation);

COMMIT;
