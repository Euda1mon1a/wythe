-- Truth Atlas Canonical PostgreSQL Schema Snapshot
-- Durable domain facts, editable rule policies, scan receipts, ratchets, and audit rulings.

BEGIN;

CREATE TABLE atlas_stack_profiles (
    id SERIAL PRIMARY KEY,
    slug VARCHAR(64) NOT NULL UNIQUE,
    label VARCHAR(128) NOT NULL,
    truth_adapter VARCHAR(64) NOT NULL,
    manipulator_adapter VARCHAR(64) NOT NULL,
    display_adapter VARCHAR(64) NOT NULL,
    implementation_status VARCHAR(32) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE atlas_targets (
    id SERIAL PRIMARY KEY,
    slug VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    repo_path TEXT NOT NULL,
    stack_profile_slug VARCHAR(64) NOT NULL REFERENCES atlas_stack_profiles(slug) ON DELETE RESTRICT,
    backend_subdir VARCHAR(128) NOT NULL DEFAULT 'backend',
    frontend_subdir VARCHAR(128) NOT NULL DEFAULT 'frontend',
    legacy_snapshot_relpath TEXT,
    description TEXT NOT NULL DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(64) NOT NULL DEFAULT 'system-seed',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE atlas_rule_policies (
    id SERIAL PRIMARY KEY,
    rule_code VARCHAR(32) NOT NULL UNIQUE,
    tier VARCHAR(24) NOT NULL,
    category VARCHAR(64) NOT NULL,
    title VARCHAR(160) NOT NULL,
    rationale TEXT NOT NULL,
    severity VARCHAR(24) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    blocks_gate BOOLEAN NOT NULL DEFAULT TRUE,
    effective_from DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_until DATE,
    updated_by VARCHAR(64) NOT NULL DEFAULT 'system-seed',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE atlas_scan_snapshots (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES atlas_targets(id) ON DELETE CASCADE,
    source_commit VARCHAR(64) NOT NULL,
    observation_source VARCHAR(64) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ NOT NULL,
    content_digest VARCHAR(64) NOT NULL,
    truth_node_count INTEGER NOT NULL,
    manipulator_node_count INTEGER NOT NULL,
    display_node_count INTEGER NOT NULL,
    verified_edge_count INTEGER NOT NULL,
    blocking_finding_count INTEGER NOT NULL,
    warning_finding_count INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE atlas_ratchet_baselines (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES atlas_targets(id) ON DELETE CASCADE,
    rule_code VARCHAR(32) NOT NULL REFERENCES atlas_rule_policies(rule_code) ON DELETE CASCADE,
    max_allowed_count INTEGER NOT NULL,
    recorded_commit VARCHAR(64) NOT NULL,
    recorded_by VARCHAR(64) NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    note TEXT NOT NULL DEFAULT '',
    CONSTRAINT uq_ratchet_target_rule UNIQUE (target_id, rule_code)
);

CREATE TABLE atlas_audit_rulings (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES atlas_targets(id) ON DELETE CASCADE,
    node_id VARCHAR(160) NOT NULL,
    disposition VARCHAR(48) NOT NULL,
    summary TEXT NOT NULL,
    cutover_history TEXT,
    audited_commit VARCHAR(64) NOT NULL,
    audited_at DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_from DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_until DATE,
    recorded_by VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE atlas_policy_vocabularies (
    id SERIAL PRIMARY KEY,
    domain_pack VARCHAR(32) NOT NULL,
    token VARCHAR(64) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(64) NOT NULL DEFAULT 'system-seed',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_policy_vocab_pack_token UNIQUE (domain_pack, token)
);

CREATE OR REPLACE FUNCTION assert_truth_atlas_write_lane()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Append-only receipt protection: scan snapshots cannot have their digest mutated.
    IF TG_OP = 'UPDATE' AND NEW.content_digest <> OLD.content_digest THEN
        RAISE EXCEPTION 'atlas_scan_snapshots are immutable receipts; create a new snapshot row';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_guard_scan_snapshot_immutability
BEFORE UPDATE ON atlas_scan_snapshots
FOR EACH ROW
EXECUTE FUNCTION assert_truth_atlas_write_lane();

COMMIT;
