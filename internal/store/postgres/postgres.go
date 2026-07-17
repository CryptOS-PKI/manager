package postgres

/*
Apache License 2.0

Copyright 2026 Shane

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"context"
	"errors"
	"fmt"

	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is a store.Store backed by Postgres. State is durable: pending
// enrollments and the audit chain survive a restart.
type Store struct {
	pool *pgxpool.Pool
}

// compile-time proof that Store satisfies the store.Store interface.
var _ store.Store = (*Store)(nil)

// New opens a connection pool to dsn, applies the schema migration, and
// returns a ready Store. The caller owns the Store and must Close it.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// bg is the context used by the interface methods, which are context-free to
// match store.Store; Postgres calls always need one.
func bg() context.Context { return context.Background() }

// Nodes returns every node in the inventory.
func (s *Store) Nodes() []store.Node {
	rows, err := s.pool.Query(bg(),
		`SELECT name, endpoint, role, admin_cert, admin_key, ca_cert FROM nodes ORDER BY name`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query nodes: %v", err))
	}
	defer rows.Close()

	out := make([]store.Node, 0)
	for rows.Next() {
		var n store.Node
		if err := rows.Scan(&n.Name, &n.Endpoint, &n.Role, &n.AdminCert, &n.AdminKey, &n.CACert); err != nil {
			panic(fmt.Sprintf("postgres: scan node: %v", err))
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate nodes: %v", err))
	}
	return out
}

// Node returns the node with the given name, and whether it was found.
func (s *Store) Node(name string) (store.Node, bool) {
	var n store.Node
	err := s.pool.QueryRow(bg(),
		`SELECT name, endpoint, role, admin_cert, admin_key, ca_cert FROM nodes WHERE name = $1`, name).
		Scan(&n.Name, &n.Endpoint, &n.Role, &n.AdminCert, &n.AdminKey, &n.CACert)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Node{}, false
	}
	if err != nil {
		panic(fmt.Sprintf("postgres: query node %q: %v", name, err))
	}
	return n, true
}

// Profiles returns every certificate issuance profile.
func (s *Store) Profiles() []store.Profile {
	rows, err := s.pool.Query(bg(),
		`SELECT name, key_alg, key_usage, ext_key_usage, is_ca, path_len, sans, validity_days
		 FROM profiles ORDER BY name`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query profiles: %v", err))
	}
	defer rows.Close()

	out := make([]store.Profile, 0)
	for rows.Next() {
		var p store.Profile
		if err := rows.Scan(&p.Name, &p.KeyAlg, &p.KeyUsage, &p.ExtKeyUsage, &p.IsCA, &p.PathLen, &p.Sans, &p.ValidityDays); err != nil {
			panic(fmt.Sprintf("postgres: scan profile: %v", err))
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate profiles: %v", err))
	}
	return out
}

// Adapters returns every enrollment protocol adapter.
func (s *Store) Adapters() []store.Adapter {
	rows, err := s.pool.Query(bg(),
		`SELECT name, kind, endpoint, profile, enabled, challenges, gpo_template
		 FROM adapters ORDER BY name`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query adapters: %v", err))
	}
	defer rows.Close()

	out := make([]store.Adapter, 0)
	for rows.Next() {
		var a store.Adapter
		if err := rows.Scan(&a.Name, &a.Kind, &a.Endpoint, &a.Profile, &a.Enabled, &a.Challenges, &a.GPOTemplate); err != nil {
			panic(fmt.Sprintf("postgres: scan adapter: %v", err))
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate adapters: %v", err))
	}
	return out
}

// Audit returns every audit event ordered by append sequence.
func (s *Store) Audit() []store.AuditEvent {
	rows, err := s.pool.Query(bg(),
		`SELECT id, at, kind, summary, target_kind, target_path, prev_hash, hash
		 FROM audit_events ORDER BY seq`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query audit_events: %v", err))
	}
	defer rows.Close()

	out := make([]store.AuditEvent, 0)
	for rows.Next() {
		var e store.AuditEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Kind, &e.Summary, &e.TargetKind, &e.TargetPath, &e.PrevHash, &e.Hash); err != nil {
			panic(fmt.Sprintf("postgres: scan audit event: %v", err))
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate audit_events: %v", err))
	}
	return out
}

// Enrollments returns every enrollment request.
func (s *Store) Enrollments() []store.Enrollment {
	rows, err := s.pool.Query(bg(), selectEnrollment+` ORDER BY requested_at, id`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query enrollments: %v", err))
	}
	defer rows.Close()

	out := make([]store.Enrollment, 0)
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			panic(fmt.Sprintf("postgres: scan enrollment: %v", err))
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate enrollments: %v", err))
	}
	return out
}

// Enrollment returns the enrollment request with the given ID, and whether it
// was found.
func (s *Store) Enrollment(id string) (store.Enrollment, bool) {
	row := s.pool.QueryRow(bg(), selectEnrollment+` WHERE id = $1`, id)
	e, err := scanEnrollment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Enrollment{}, false
	}
	if err != nil {
		panic(fmt.Sprintf("postgres: query enrollment %q: %v", id, err))
	}
	return e, true
}

// AddEnrollment appends a new enrollment request.
func (s *Store) AddEnrollment(e store.Enrollment) {
	if _, err := s.pool.Exec(bg(), insertEnrollment, enrollmentArgs(e)...); err != nil {
		panic(fmt.Sprintf("postgres: insert enrollment %q: %v", e.ID, err))
	}
}

// UpdateEnrollment reads the enrollment with the given ID, applies mutate to it
// in Go, and writes every column back, all in one transaction. It returns an
// error if no enrollment has that ID.
func (s *Store) UpdateEnrollment(id string, mutate func(*store.Enrollment)) error {
	ctx := bg()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin enrollment update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, selectEnrollment+` WHERE id = $1`, id)
	e, err := scanEnrollment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: enrollment %q not found", id)
	}
	if err != nil {
		return fmt.Errorf("postgres: load enrollment %q: %w", id, err)
	}

	mutate(&e)

	if _, err := tx.Exec(ctx, updateEnrollment, updateEnrollmentArgs(e)...); err != nil {
		return fmt.Errorf("postgres: update enrollment %q: %w", id, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit enrollment update: %w", err)
	}
	return nil
}

// AddAuditEvent appends e to the hash-chained audit log: it reads the most
// recent event's hash as prev_hash (empty for the first event), computes the
// new hash, persists the row, and returns the stored event. The read and insert
// run in one transaction so concurrent appends cannot fork the chain.
func (s *Store) AddAuditEvent(e store.AuditEvent) store.AuditEvent {
	ctx := bg()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		panic(fmt.Sprintf("postgres: begin audit append: %v", err))
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var prev string
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		panic(fmt.Sprintf("postgres: read last audit hash: %v", err))
	}

	e.PrevHash = prev
	e.Hash = store.HashEvent(prev, e)

	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_events (id, at, kind, summary, target_kind, target_path, prev_hash, hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.ID, e.At, e.Kind, e.Summary, e.TargetKind, e.TargetPath, e.PrevHash, e.Hash); err != nil {
		panic(fmt.Sprintf("postgres: insert audit event %q: %v", e.ID, err))
	}
	if err := tx.Commit(ctx); err != nil {
		panic(fmt.Sprintf("postgres: commit audit append: %v", err))
	}
	return e
}

// SeedIfEmpty inserts the given catalog only when every target table is empty,
// so restarts never duplicate or clobber live data. The check and the inserts
// run in one transaction.
func (s *Store) SeedIfEmpty(ctx context.Context, nodes []store.Node, profiles []store.Profile, adapters []store.Adapter, audit []store.AuditEvent, enrollments []store.Enrollment) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin seed: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	empty, err := allTablesEmpty(ctx, tx)
	if err != nil {
		return err
	}
	if !empty {
		return tx.Commit(ctx)
	}

	for _, n := range nodes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO nodes (name, endpoint, role, admin_cert, admin_key, ca_cert)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			n.Name, n.Endpoint, n.Role, n.AdminCert, n.AdminKey, n.CACert); err != nil {
			return fmt.Errorf("postgres: seed node %q: %w", n.Name, err)
		}
	}
	for _, p := range profiles {
		if _, err := tx.Exec(ctx,
			`INSERT INTO profiles (name, key_alg, key_usage, ext_key_usage, is_ca, path_len, sans, validity_days)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			p.Name, p.KeyAlg, nonNil(p.KeyUsage), nonNil(p.ExtKeyUsage), p.IsCA, p.PathLen, nonNil(p.Sans), p.ValidityDays); err != nil {
			return fmt.Errorf("postgres: seed profile %q: %w", p.Name, err)
		}
	}
	for _, a := range adapters {
		if _, err := tx.Exec(ctx,
			`INSERT INTO adapters (name, kind, endpoint, profile, enabled, challenges, gpo_template)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			a.Name, a.Kind, a.Endpoint, a.Profile, a.Enabled, nonNil(a.Challenges), a.GPOTemplate); err != nil {
			return fmt.Errorf("postgres: seed adapter %q: %w", a.Name, err)
		}
	}
	for _, ev := range audit {
		if _, err := tx.Exec(ctx,
			`INSERT INTO audit_events (id, at, kind, summary, target_kind, target_path, prev_hash, hash)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			ev.ID, ev.At, ev.Kind, ev.Summary, ev.TargetKind, ev.TargetPath, ev.PrevHash, ev.Hash); err != nil {
			return fmt.Errorf("postgres: seed audit event %q: %w", ev.ID, err)
		}
	}
	for _, en := range enrollments {
		if _, err := tx.Exec(ctx, insertEnrollment, enrollmentArgs(en)...); err != nil {
			return fmt.Errorf("postgres: seed enrollment %q: %w", en.ID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit seed: %w", err)
	}
	return nil
}

// allTablesEmpty reports whether every seedable table has zero rows.
func allTablesEmpty(ctx context.Context, tx pgx.Tx) (bool, error) {
	var total int
	err := tx.QueryRow(ctx,
		`SELECT (SELECT count(*) FROM nodes)
		      + (SELECT count(*) FROM profiles)
		      + (SELECT count(*) FROM adapters)
		      + (SELECT count(*) FROM audit_events)
		      + (SELECT count(*) FROM enrollments)`).Scan(&total)
	if err != nil {
		return false, fmt.Errorf("postgres: count for seed guard: %w", err)
	}
	return total == 0, nil
}

// nonNil replaces a nil slice with an empty one so a NOT NULL text[] column
// never receives NULL (the store's zero value for an absent list is nil).
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// selectEnrollment is the shared column list for reading an enrollment; append
// a WHERE/ORDER BY clause as needed.
const selectEnrollment = `SELECT id, proposed_name, role, parent_cn, address, status,
	attestation_summary, attestation_node_id, csr_key_type, csr_subject_cn,
	requested_at, rejection_reason, admitted_node_name, kind, pinned_key_sha256,
	attestation_ok, profile FROM enrollments`

const insertEnrollment = `INSERT INTO enrollments (
	id, proposed_name, role, parent_cn, address, status,
	attestation_summary, attestation_node_id, csr_key_type, csr_subject_cn,
	requested_at, rejection_reason, admitted_node_name, kind, pinned_key_sha256,
	attestation_ok, profile
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`

const updateEnrollment = `UPDATE enrollments SET
	proposed_name=$2, role=$3, parent_cn=$4, address=$5, status=$6,
	attestation_summary=$7, attestation_node_id=$8, csr_key_type=$9, csr_subject_cn=$10,
	requested_at=$11, rejection_reason=$12, admitted_node_name=$13, kind=$14,
	pinned_key_sha256=$15, attestation_ok=$16, profile=$17
WHERE id=$1`

// enrollmentArgs lays out an Enrollment in the column order used by both the
// insert and update statements.
func enrollmentArgs(e store.Enrollment) []any {
	return []any{
		e.ID, e.ProposedName, e.Role, e.ParentCN, e.Address, e.Status,
		e.AttestationSummary, e.AttestationNodeID, e.CSRKeyType, e.CSRSubjectCN,
		e.RequestedAt, e.RejectionReason, e.AdmittedNodeName, e.Kind, e.PinnedKeySHA256,
		e.AttestationOK, e.Profile,
	}
}

// updateEnrollmentArgs mirrors enrollmentArgs; the id stays $1 as the WHERE key
// while the remaining columns are rewritten.
func updateEnrollmentArgs(e store.Enrollment) []any {
	return enrollmentArgs(e)
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows, letting scanEnrollment
// serve the single-row and iterating callers.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanEnrollment reads one enrollment row in the selectEnrollment column order.
func scanEnrollment(r rowScanner) (store.Enrollment, error) {
	var e store.Enrollment
	err := r.Scan(
		&e.ID, &e.ProposedName, &e.Role, &e.ParentCN, &e.Address, &e.Status,
		&e.AttestationSummary, &e.AttestationNodeID, &e.CSRKeyType, &e.CSRSubjectCN,
		&e.RequestedAt, &e.RejectionReason, &e.AdmittedNodeName, &e.Kind, &e.PinnedKeySHA256,
		&e.AttestationOK, &e.Profile,
	)
	return e, err
}
