CREATE TABLE IF NOT EXISTS nodes (
  name text PRIMARY KEY, endpoint text NOT NULL, role text NOT NULL,
  admin_cert text NOT NULL, admin_key text NOT NULL, ca_cert text NOT NULL
);
CREATE TABLE IF NOT EXISTS profiles (
  name text PRIMARY KEY, key_alg text NOT NULL, key_usage text[] NOT NULL,
  ext_key_usage text[] NOT NULL, is_ca boolean NOT NULL, path_len int NOT NULL,
  sans text[] NOT NULL, validity_days int NOT NULL
);
CREATE TABLE IF NOT EXISTS adapters (
  name text PRIMARY KEY, kind text NOT NULL, endpoint text NOT NULL,
  profile text NOT NULL, enabled boolean NOT NULL, challenges text[] NOT NULL,
  gpo_template text NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  seq bigserial PRIMARY KEY, id text UNIQUE NOT NULL, at text NOT NULL,
  kind text NOT NULL, summary text NOT NULL, target_kind text NOT NULL,
  target_path text NOT NULL, prev_hash text NOT NULL, hash text NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollments (
  id text PRIMARY KEY, proposed_name text NOT NULL, role text NOT NULL,
  parent_cn text NOT NULL, address text NOT NULL, status text NOT NULL,
  attestation_summary text NOT NULL, attestation_node_id text NOT NULL,
  csr_key_type text NOT NULL, csr_subject_cn text NOT NULL,
  requested_at text NOT NULL, rejection_reason text NOT NULL,
  admitted_node_name text NOT NULL, kind text NOT NULL,
  pinned_key_sha256 text NOT NULL, attestation_ok boolean NOT NULL,
  profile text NOT NULL
);
