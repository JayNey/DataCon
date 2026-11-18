BEGIN;

-- Serialize concurrent migration runs, matching the earlier migrations.
SELECT pg_advisory_xact_lock(hashtext('datacon:migrations'));

-- Verifiable migration ledger. Every supported apply path (`datacon migrate`
-- and the workflow bootstrap) records the exact filename and sha256 it ran, so
-- promotion can prove the database schema matches the candidate manifest
-- instead of trusting an approval boolean.
CREATE TABLE IF NOT EXISTS schema_migrations (
    file text PRIMARY KEY,
    sha256 text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT schema_migrations_file_check
        CHECK (file ~ '^[0-9]{3}_[A-Za-z0-9_]+\.sql$'),
    CONSTRAINT schema_migrations_sha256_check
        CHECK (sha256 ~ '^sha256:[0-9a-f]{64}$')
);

-- The currently active control-plane release for one protected environment.
-- Promotion and rollback both mutate this row inside their own transaction; a
-- workflow can never invent the active slots or previous release.
CREATE TABLE IF NOT EXISTS release_state (
    environment text PRIMARY KEY,
    image_id text NOT NULL,
    config jsonb NOT NULL DEFAULT '{}'::jsonb,
    migration_version text NOT NULL,
    evidence_root text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT release_state_image_id_check
        CHECK (image_id ~ '^sha256:[0-9a-f]{64}$')
);

-- Append-only audit log. ``bootstrap`` records the baseline snapshot so a
-- promotion that overwrites release_state cannot lose the rollback target.
-- Only successful promotions are unique per (environment, candidate_digest),
-- keeping repeated promotions idempotent while allowing multiple rollbacks
-- (including repeated smoke failures or rolling back to the same baseline
-- image more than once).
CREATE TABLE IF NOT EXISTS release_events (
    event_id uuid PRIMARY KEY,
    environment text NOT NULL,
    action text NOT NULL,
    status text NOT NULL,
    candidate_digest text NOT NULL,
    manifest_digest text NOT NULL,
    previous_image_id text,
    active_image_id text NOT NULL,
    payload jsonb NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT release_events_action_check
        CHECK (action IN ('promote', 'rollback', 'bootstrap')),
    CONSTRAINT release_events_status_check
        CHECK (status IN ('promoted', 'rolled_back', 'bootstrapped')),
    CONSTRAINT release_events_candidate_digest_check
        CHECK (candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT release_events_manifest_digest_check
        CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$')
);

-- Upgrade databases created by the previous revision of this migration.
-- Dropping and re-adding the named constraints is idempotent and preserves
-- existing promote/rollback rows.
ALTER TABLE release_events
    DROP CONSTRAINT IF EXISTS release_events_action_check;
ALTER TABLE release_events
    ADD CONSTRAINT release_events_action_check
    CHECK (action IN ('promote', 'rollback', 'bootstrap'));
ALTER TABLE release_events
    DROP CONSTRAINT IF EXISTS release_events_status_check;
ALTER TABLE release_events
    ADD CONSTRAINT release_events_status_check
    CHECK (status IN ('promoted', 'rolled_back', 'bootstrapped'));

-- Remove the legacy three-column unique constraint; the partial promote index
-- below is the source of truth for promotion idempotency.
ALTER TABLE release_events
    DROP CONSTRAINT IF EXISTS release_events_environment_action_candidate_digest_key;

CREATE UNIQUE INDEX IF NOT EXISTS release_events_promote_unique_idx
    ON release_events (environment, candidate_digest)
    WHERE action = 'promote';

-- One baseline snapshot per environment, so bootstrap is idempotent.
CREATE UNIQUE INDEX IF NOT EXISTS release_events_bootstrap_unique_idx
    ON release_events (environment)
    WHERE action = 'bootstrap';

CREATE INDEX IF NOT EXISTS release_events_recorded_idx
    ON release_events (environment, recorded_at DESC);

COMMIT;
