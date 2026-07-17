// Package postgres implements store.Store against a hand-rolled Postgres
// backend using raw SQL over pgx. No ORM, no query builder.
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
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// schemaSQL is the full DDL for the manager's tables, applied once by migrate.
//
//go:embed schema.sql
var schemaSQL string

// schemaVersion is the single migration version tracked in schema_migrations.
// The schema ships as one embedded DDL blob; when it changes, bump this and add
// the new statements to schema.sql (every table is created IF NOT EXISTS).
const schemaVersion = "v1"

// migrate applies schema.sql exactly once, tracked in a schema_migrations
// table, and is safe to run on every startup. Running it against an
// already-migrated database is a no-op.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return fmt.Errorf("postgres: create schema_migrations: %w", err)
	}

	var applied bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
		schemaVersion).Scan(&applied); err != nil {
		return fmt.Errorf("postgres: check migration %s: %w", schemaVersion, err)
	}
	if applied {
		return tx.Commit(ctx)
	}

	if _, err := tx.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("postgres: apply schema %s: %w", schemaVersion, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1)`, schemaVersion); err != nil {
		return fmt.Errorf("postgres: record migration %s: %w", schemaVersion, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit migration: %w", err)
	}
	return nil
}
