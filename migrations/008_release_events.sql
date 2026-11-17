BEGIN;

-- Serialize concurrent migration runs, matching the earlier migrations.
SELECT pg_advisory_xact_lock(hashtext('datacon:migrations'));

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

-- Append-only audit log. Only successful promotions are unique per
-- (environment, candidate_digest), keeping repeated promotions idempotent while
-- allowing multiple rollbacks (including repeated smoke failures or rolling back
-- to the same baseline image more than once).
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
        CHECK (action IN ('promote', 'rollback')),
    CONSTRAINT release_events_status_check
        CHECK (status IN ('promoted', 'rolled_back')),
    CONSTRAINT release_events_candidate_digest_check
        CHECK (candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT release_events_manifest_digest_check
        CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$')
);

ALTER TABLE release_events
    DROP CONSTRAINT IF EXISTS release_events_environment_action_candidate_digest_key;

CREATE UNIQUE INDEX IF NOT EXISTS release_events_promote_unique_idx
    ON release_events (environment, candidate_digest)
    WHERE action = 'promote';

CREATE INDEX IF NOT EXISTS release_events_recorded_idx
    ON release_events (environment, recorded_at DESC);

COMMIT;
