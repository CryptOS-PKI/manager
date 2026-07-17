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
	"fmt"
	"sync"
	"testing"

	"github.com/CryptOS-PKI/manager/internal/store"
)

func TestNodeRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO nodes (name, endpoint, role, admin_cert, admin_key, ca_cert)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		"x", "x.example:443", "root", "cert", "key", "ca"); err != nil {
		t.Fatalf("insert node: %v", err)
	}

	got, ok := s.Node("x")
	if !ok {
		t.Fatal("Node(x) not found")
	}
	if got.Endpoint != "x.example:443" || got.Role != "root" || got.CACert != "ca" {
		t.Fatalf("Node(x) = %+v, unexpected fields", got)
	}

	if _, ok := s.Node("missing"); ok {
		t.Fatal("Node(missing) returned found")
	}

	all := s.Nodes()
	if len(all) != 1 || all[0].Name != "x" {
		t.Fatalf("Nodes() = %+v, want single node x", all)
	}
}

func TestProfileAndAdapterReads(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO profiles (name, key_alg, key_usage, ext_key_usage, is_ca, path_len, sans, validity_days)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		"p1", "ECDSA-P384", []string{"digital_signature"}, []string{"server_auth"}, false, 0, []string{"a.example"}, 365); err != nil {
		t.Fatalf("insert profile: %v", err)
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO adapters (name, kind, endpoint, profile, enabled, challenges, gpo_template)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		"acme", "acme", "https://x/acme", "p1", true, []string{"http-01", "dns-01"}, ""); err != nil {
		t.Fatalf("insert adapter: %v", err)
	}

	profiles := s.Profiles()
	if len(profiles) != 1 || profiles[0].KeyAlg != "ECDSA-P384" || len(profiles[0].Sans) != 1 || profiles[0].Sans[0] != "a.example" {
		t.Fatalf("Profiles() = %+v, unexpected", profiles)
	}

	adapters := s.Adapters()
	if len(adapters) != 1 || !adapters[0].Enabled || len(adapters[0].Challenges) != 2 {
		t.Fatalf("Adapters() = %+v, unexpected", adapters)
	}
}

func TestEnrollmentMutations(t *testing.T) {
	s := testStore(t)

	e := store.Enrollment{
		ID:           "enr-abc",
		Kind:         "LINK",
		Status:       "PENDING",
		ProposedName: "node-1",
		RequestedAt:  "2026-07-17T00:00:00Z",
	}
	s.AddEnrollment(e)

	got, ok := s.Enrollment("enr-abc")
	if !ok || got.Status != "PENDING" || got.ProposedName != "node-1" {
		t.Fatalf("Enrollment after add = %+v, ok=%v", got, ok)
	}

	if err := s.UpdateEnrollment("enr-abc", func(en *store.Enrollment) {
		en.Status = "APPROVED"
		en.AdmittedNodeName = "node-1"
	}); err != nil {
		t.Fatalf("UpdateEnrollment: %v", err)
	}

	got, _ = s.Enrollment("enr-abc")
	if got.Status != "APPROVED" || got.AdmittedNodeName != "node-1" {
		t.Fatalf("Enrollment after update = %+v, want APPROVED/node-1", got)
	}

	if err := s.UpdateEnrollment("missing", func(*store.Enrollment) {}); err == nil {
		t.Fatal("UpdateEnrollment(missing) = nil, want error")
	}

	all := s.Enrollments()
	if len(all) != 1 {
		t.Fatalf("Enrollments() len = %d, want 1", len(all))
	}
}

func TestAuditChain(t *testing.T) {
	s := testStore(t)

	first := s.AddAuditEvent(store.AuditEvent{ID: "a1", At: "t1", Kind: "issued", Summary: "one"})
	second := s.AddAuditEvent(store.AuditEvent{ID: "a2", At: "t2", Kind: "revoked", Summary: "two"})

	if first.Hash == "" || second.Hash == "" {
		t.Fatal("hashes must be non-empty")
	}
	if first.PrevHash != "" {
		t.Fatalf("first PrevHash = %q, want empty", first.PrevHash)
	}
	if second.PrevHash != first.Hash {
		t.Fatalf("second PrevHash = %q, want first Hash %q", second.PrevHash, first.Hash)
	}
	if first.Hash == second.Hash {
		t.Fatal("distinct events must have distinct hashes")
	}

	log := s.Audit()
	if len(log) != 2 || log[0].ID != "a1" || log[1].ID != "a2" {
		t.Fatalf("Audit() = %+v, want ordered a1,a2", log)
	}
	if log[1].PrevHash != log[0].Hash {
		t.Fatalf("persisted chain broken: log[1].PrevHash=%q log[0].Hash=%q", log[1].PrevHash, log[0].Hash)
	}
}

// TestAuditChainConcurrentAppends drives many concurrent AddAuditEvent calls
// against one store and asserts the persisted chain stays linear: every event
// links to its predecessor, no prev_hash is reused, and every append lands.
// Without the advisory lock in AddAuditEvent two appends could read the same
// prev_hash and fork the chain, which this test would catch.
func TestAuditChainConcurrentAppends(t *testing.T) {
	s := testStore(t)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			s.AddAuditEvent(store.AuditEvent{
				ID:      fmt.Sprintf("evt-%d", i),
				At:      "t",
				Kind:    "issued",
				Summary: fmt.Sprintf("append %d", i),
			})
		}(i)
	}
	wg.Wait()

	log := s.Audit()
	if len(log) != n {
		t.Fatalf("Audit() len = %d, want %d", len(log), n)
	}

	seenPrev := make(map[string]struct{}, n)
	for i, e := range log {
		if e.Hash == "" {
			t.Fatalf("event %d has empty hash", i)
		}
		if i == 0 {
			if e.PrevHash != "" {
				t.Fatalf("first event PrevHash = %q, want empty", e.PrevHash)
			}
		} else {
			if e.PrevHash != log[i-1].Hash {
				t.Fatalf("chain fork at %d: PrevHash=%q, want prior Hash %q", i, e.PrevHash, log[i-1].Hash)
			}
		}
		if _, dup := seenPrev[e.PrevHash]; dup && e.PrevHash != "" {
			t.Fatalf("duplicate PrevHash %q at event %d: chain forked", e.PrevHash, i)
		}
		seenPrev[e.PrevHash] = struct{}{}
	}
}

func TestSeedIfEmpty(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	nodes := []store.Node{{Name: "n1", Endpoint: "n1:443", Role: "root", AdminCert: "c", AdminKey: "k", CACert: "ca"}}
	profiles := []store.Profile{{Name: "p1", KeyAlg: "ECDSA-P384", ValidityDays: 365}}
	adapters := []store.Adapter{{Name: "acme", Kind: "acme", Endpoint: "https://x", Profile: "p1", Enabled: true}}
	audit := []store.AuditEvent{{ID: "aud-0", At: "t0", Kind: "issued", Summary: "seed"}}
	enrollments := []store.Enrollment{{ID: "enr-0", Kind: "LINK", Status: "PENDING", ProposedName: "n1", RequestedAt: "t0"}}

	if err := s.SeedIfEmpty(ctx, nodes, profiles, adapters, audit, enrollments); err != nil {
		t.Fatalf("first SeedIfEmpty: %v", err)
	}
	if len(s.Nodes()) != 1 || len(s.Profiles()) != 1 || len(s.Adapters()) != 1 || len(s.Audit()) != 1 || len(s.Enrollments()) != 1 {
		t.Fatal("first seed did not populate every table")
	}

	// A second seed is a no-op: counts must not change.
	if err := s.SeedIfEmpty(ctx, nodes, profiles, adapters, audit, enrollments); err != nil {
		t.Fatalf("second SeedIfEmpty: %v", err)
	}
	if len(s.Nodes()) != 1 || len(s.Enrollments()) != 1 {
		t.Fatalf("second seed duplicated rows: nodes=%d enrollments=%d", len(s.Nodes()), len(s.Enrollments()))
	}
}
