BEGIN;

-- Serialize concurrent migration runs, matching 005-009. The DO blocks below
-- check pg_constraint before adding a constraint; without this lock two
-- concurrent runners can both observe a constraint as missing and one
-- ADD CONSTRAINT fails. The lock is transaction-scoped, so it is released even
-- if the migration aborts.
SELECT pg_advisory_xact_lock(hashtext('datacon:migrations'));

-- T10 v2 identity and review persistence. Everything here is additive: the
-- existing reason_code column (001), workflow_synced/generation/lease_* (002),
-- evidence_* (005) and the jobs_archived_evidence_check invariant (007) are
-- never rebuilt, dropped or redefined. family COMPLETED relies on 007 staying
-- exactly as written.
--
-- v1 rows keep job_contract_version=1 and leave family_id/job_kind/
-- parent_job_id/round_no NULL; v2 rows set job_contract_version=2 and branch on
-- job_kind (family/campaign/round). Once this file is frozen it must not be
-- edited; later changes append 011_*.sql instead.
ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS family_id uuid,
    ADD COLUMN IF NOT EXISTS job_kind text,
    ADD COLUMN IF NOT EXISTS parent_job_id uuid REFERENCES jobs(job_id),
    ADD COLUMN IF NOT EXISTS round_no integer,
    ADD COLUMN IF NOT EXISTS job_contract_version integer NOT NULL DEFAULT 1;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'jobs'::regclass
          AND conname = 'jobs_job_contract_version_check'
    ) THEN
        ALTER TABLE jobs ADD CONSTRAINT jobs_job_contract_version_check
            CHECK (job_contract_version IN (1, 2));
    END IF;

    -- Full v1/v2 branch. CHECK passes on NULL, so the v2 branch also requires
    -- jobs_v2_identity_not_null below to keep job_kind/family_id non-null.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'jobs'::regclass
          AND conname = 'jobs_identity_check'
    ) THEN
        ALTER TABLE jobs ADD CONSTRAINT jobs_identity_check
            CHECK (
                (job_contract_version = 1
                 AND family_id IS NULL AND job_kind IS NULL
                 AND parent_job_id IS NULL AND round_no IS NULL)
                OR
                (job_contract_version = 2 AND (
                    (job_kind = 'family' AND parent_job_id IS NULL
                     AND round_no IS NULL AND family_id = job_id)
                    OR
                    (job_kind = 'campaign' AND parent_job_id IS NOT NULL
                     AND round_no IS NULL AND family_id = parent_job_id
                     AND parent_job_id <> job_id)
                    OR
                    (job_kind = 'round' AND parent_job_id IS NOT NULL
                     AND round_no IS NOT NULL AND round_no >= 1
                     AND family_id = parent_job_id
                     AND parent_job_id <> job_id)
                ))
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'jobs'::regclass
          AND conname = 'jobs_v2_identity_not_null'
    ) THEN
        ALTER TABLE jobs ADD CONSTRAINT jobs_v2_identity_not_null
            CHECK (
                job_contract_version = 1
                OR (job_kind IS NOT NULL AND family_id IS NOT NULL)
            );
    END IF;
END $$;

-- At most one child per (parent, round); campaign rows have round_no NULL and
-- are therefore unaffected. The partial index keeps exactly one campaign per
-- family (campaign.parent_job_id is the family).
CREATE UNIQUE INDEX IF NOT EXISTS jobs_parent_round_key
    ON jobs(parent_job_id, round_no);

CREATE UNIQUE INDEX IF NOT EXISTS jobs_family_campaign_key
    ON jobs(parent_job_id) WHERE job_kind = 'campaign';

-- Human approvals are append-only. Re-approving a changed envelope appends a
-- new row whose supersedes points at the prior chain tail; UNIQUE(family_id,
-- envelope_digest) is the backstop against approving one envelope twice.
CREATE TABLE IF NOT EXISTS family_approvals (
    approval_id uuid PRIMARY KEY,
    family_id uuid NOT NULL REFERENCES jobs(job_id),
    approval_digest text NOT NULL,
    envelope_digest text NOT NULL,
    first_plan_digest text NOT NULL,
    reviewer_id text NOT NULL,
    decided_at timestamptz NOT NULL,
    supersedes uuid REFERENCES family_approvals(approval_id),
    CONSTRAINT family_approvals_approval_digest_unique UNIQUE (approval_digest),
    CONSTRAINT family_approvals_envelope_unique UNIQUE (family_id, envelope_digest)
);

-- A family's pending review envelope is its own row, not a copy of a plan: this
-- is what distinguishes the first human approval from a changed-envelope
-- re-approval. Rows are never deleted; the old row moves to approved/rejected/
-- expired, and the partial unique index keeps at most one pending row.
CREATE TABLE IF NOT EXISTS family_envelopes (
    envelope_id uuid PRIMARY KEY,
    family_id uuid NOT NULL REFERENCES jobs(job_id),
    envelope_digest text NOT NULL,
    envelope_json jsonb NOT NULL,
    status text NOT NULL,
    review_deadline_at timestamptz NOT NULL
        DEFAULT (clock_timestamp() + interval '24 hours'),
    reviewer_id text,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT family_envelopes_digest_unique UNIQUE (family_id, envelope_digest),
    CONSTRAINT family_envelopes_status_check
        CHECK (status IN ('pending', 'approved', 'rejected', 'expired'))
);

CREATE UNIQUE INDEX IF NOT EXISTS family_envelopes_one_pending
    ON family_envelopes(family_id) WHERE status = 'pending';

-- Automatic policy admission for a v2 round. There is at most one policy
-- admission per (parent, round); recomputable=false must still carry the
-- supporting composite digest that makes the decision auditable.
CREATE TABLE IF NOT EXISTS admissions (
    admission_id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES jobs(job_id),
    parent_job_id uuid NOT NULL REFERENCES jobs(job_id),
    round_no integer NOT NULL CHECK (round_no >= 1),
    approval_kind text NOT NULL CHECK (approval_kind = 'policy'),
    envelope_digest text NOT NULL,
    parent_approval_digest text NOT NULL,
    seed_digest text NOT NULL,
    predicate_version text NOT NULL,
    recomputable boolean NOT NULL,
    supporting_bundle_digest text,
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT admissions_parent_round_unique UNIQUE (parent_job_id, round_no),
    CONSTRAINT admissions_supporting_check CHECK (
        recomputable = true OR supporting_bundle_digest IS NOT NULL
    )
);

-- Family budget ledger. D41: there must be no remaining_fuzz_seconds <=
-- remaining_total_seconds cross CHECK; general (build/replay) charges drain only
-- the total budget, so the fuzz sub-budget can legitimately exceed it. The
-- executable fuzz ceiling is min(remaining_total_seconds, remaining_fuzz_seconds)
-- and is enforced by the application, not by a single-column check.
CREATE TABLE IF NOT EXISTS budget_ledger (
    family_id uuid PRIMARY KEY REFERENCES jobs(job_id),
    max_total_seconds integer NOT NULL,
    max_fuzz_seconds integer NOT NULL,
    remaining_total_seconds integer NOT NULL,
    remaining_fuzz_seconds integer NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT budget_ledger_max_total_positive CHECK (max_total_seconds > 0),
    CONSTRAINT budget_ledger_max_fuzz_non_negative CHECK (max_fuzz_seconds >= 0),
    CONSTRAINT budget_ledger_total_non_negative
        CHECK (remaining_total_seconds >= 0),
    CONSTRAINT budget_ledger_fuzz_non_negative
        CHECK (remaining_fuzz_seconds >= 0),
    CONSTRAINT budget_ledger_remaining_within_max_total
        CHECK (remaining_total_seconds <= max_total_seconds),
    CONSTRAINT budget_ledger_remaining_within_max_fuzz
        CHECK (remaining_fuzz_seconds <= max_fuzz_seconds),
    CONSTRAINT budget_ledger_fuzz_within_total
        CHECK (max_fuzz_seconds <= max_total_seconds)
);

-- Idempotent charges keyed by (job_id, step_key, attempt_no): replaying the same
-- attempt must return the existing charge instead of billing twice, while a new
-- attempt_no is a new charge. family_id is denormalized for offline rebuilds.
CREATE TABLE IF NOT EXISTS budget_charges (
    charge_id uuid PRIMARY KEY,
    family_id uuid NOT NULL REFERENCES jobs(job_id),
    job_id uuid NOT NULL REFERENCES jobs(job_id),
    step_key text NOT NULL,
    attempt_no integer NOT NULL,
    charge_kind text NOT NULL,
    seconds integer NOT NULL,
    fuzz_seconds integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT budget_charges_idempotent UNIQUE (job_id, step_key, attempt_no),
    CONSTRAINT budget_charges_attempt_positive CHECK (attempt_no >= 1),
    CONSTRAINT budget_charges_seconds_non_negative CHECK (seconds >= 0),
    CONSTRAINT budget_charges_fuzz_bounded
        CHECK (fuzz_seconds >= 0 AND fuzz_seconds <= seconds),
    CONSTRAINT budget_charges_kind_matches_fuzz CHECK (
        (charge_kind = 'general' AND fuzz_seconds = 0)
        OR (charge_kind = 'fuzz' AND fuzz_seconds > 0)
    )
);

COMMIT;
