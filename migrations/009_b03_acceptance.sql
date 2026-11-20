BEGIN;

-- Serialize concurrent migration runs, matching 005-008. The CREATE TABLE
-- below is guarded and therefore safe to re-run; the advisory lock makes two
-- concurrent runners observe the same table state instead of racing.
SELECT pg_advisory_xact_lock(hashtext('datacon:migrations'));

-- A dedicated B03 acceptance ledger. It is deliberately separate from
-- release_events: B03 acceptance is a prerequisite fact for the future
-- promotion gate, not a promote/rollback transition, so the existing
-- release_events.action/status CHECK constraints stay untouched.
--
-- candidate_digest is the release candidate manifest digest produced by
-- release.canonical_manifest_digest(manifest). It is never the Docker image id:
-- control_plane_image_id is recorded separately so the acceptance can be
-- replayed against the exact image the manifest bound.
--
-- There is exactly one accepted B03 result per environment and candidate. A
-- conflicting re-record fails closed in ReleaseStore instead of silently
-- overwriting a prior acceptance.
CREATE TABLE IF NOT EXISTS b03_acceptance (
    environment text NOT NULL,
    candidate_digest text NOT NULL,
    control_plane_image_id text NOT NULL,
    b03_bundle_manifest_digest text NOT NULL,
    storage_ref text NOT NULL,
    run_id text NOT NULL,
    status text NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (environment, candidate_digest),
    CONSTRAINT b03_acceptance_status_check
        CHECK (status = 'passed'),
    CONSTRAINT b03_acceptance_candidate_digest_check
        CHECK (candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT b03_acceptance_control_plane_image_id_check
        CHECK (control_plane_image_id ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT b03_acceptance_bundle_manifest_digest_check
        CHECK (b03_bundle_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT b03_acceptance_storage_ref_check
        CHECK (btrim(storage_ref) <> ''),
    CONSTRAINT b03_acceptance_run_id_check
        CHECK (btrim(run_id) <> '')
);

COMMIT;
