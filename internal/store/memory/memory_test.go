package memory

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
	"testing"

	"github.com/CryptOS-PKI/manager/internal/store"
)

func testNodes() []store.Node {
	return []store.Node{
		{
			Name:      "pki-root",
			Endpoint:  "pki-root.acme.com:4443",
			Role:      "root",
			AdminCert: "/tmp/root/admin.crt",
			AdminKey:  "/tmp/root/admin.key",
			CACert:    "/tmp/root/ca.pem",
		},
		{
			Name:      "pki-inter",
			Endpoint:  "pki-inter.acme.com:4444",
			Role:      "intermediate",
			AdminCert: "/tmp/inter/admin.crt",
			AdminKey:  "/tmp/inter/admin.key",
			CACert:    "/tmp/inter/ca.pem",
		},
	}
}

func TestStore_Nodes(t *testing.T) {
	s := New(testNodes())

	nodes := s.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("len(Nodes()) = %d, want 2", len(nodes))
	}
}

func TestStore_Node_Found(t *testing.T) {
	s := New(testNodes())

	n, ok := s.Node("pki-root")
	if !ok {
		t.Fatal("Node(\"pki-root\") ok = false, want true")
	}
	if n.Endpoint != "pki-root.acme.com:4443" {
		t.Errorf("Node(\"pki-root\").Endpoint = %q, want pki-root.acme.com:4443", n.Endpoint)
	}
}

func TestStore_Node_NotFound(t *testing.T) {
	s := New(testNodes())

	_, ok := s.Node("does-not-exist")
	if ok {
		t.Fatal("Node(\"does-not-exist\") ok = true, want false")
	}
}

func TestStore_ImplementsInterface(t *testing.T) {
	var _ store.Store = New(testNodes())
}

func testCatalog() ([]store.Profile, []store.Adapter, []store.AuditEvent, []store.Enrollment) {
	profiles := []store.Profile{
		{Name: "TLS Server (LDAPS)", KeyAlg: "ECDSA-P384", ValidityDays: 365},
	}
	adapters := []store.Adapter{
		{Kind: "acme", Name: "ACME (RFC 8555)", Enabled: true},
	}
	audit := []store.AuditEvent{
		{ID: "aud-0000", Kind: "issued", Summary: "Issued leaf svc-1.acme.example"},
	}
	enrollments := []store.Enrollment{
		{ID: "enr-0001", ProposedName: "acme-issuing-04", Status: "PENDING"},
	}

	return profiles, adapters, audit, enrollments
}

func TestStore_New_HasEmptyCatalog(t *testing.T) {
	s := New(testNodes())

	if got := s.Profiles(); len(got) != 0 {
		t.Errorf("Profiles() len = %d, want 0", len(got))
	}
	if got := s.Adapters(); len(got) != 0 {
		t.Errorf("Adapters() len = %d, want 0", len(got))
	}
	if got := s.Audit(); len(got) != 0 {
		t.Errorf("Audit() len = %d, want 0", len(got))
	}
	if got := s.Enrollments(); len(got) != 0 {
		t.Errorf("Enrollments() len = %d, want 0", len(got))
	}
}

func TestStore_NewWithCatalog_RoundTrip(t *testing.T) {
	profiles, adapters, audit, enrollments := testCatalog()

	s := NewWithCatalog(testNodes(), profiles, adapters, audit, enrollments)

	if got := s.Profiles(); len(got) != 1 || got[0].Name != "TLS Server (LDAPS)" {
		t.Errorf("Profiles() = %+v, want the seeded profile", got)
	}
	if got := s.Adapters(); len(got) != 1 || got[0].Kind != "acme" {
		t.Errorf("Adapters() = %+v, want the seeded adapter", got)
	}
	if got := s.Audit(); len(got) != 1 || got[0].ID != "aud-0000" {
		t.Errorf("Audit() = %+v, want the seeded event", got)
	}
	if got := s.Enrollments(); len(got) != 1 || got[0].Status != "PENDING" {
		t.Errorf("Enrollments() = %+v, want the seeded enrollment", got)
	}

	// Nodes() is unaffected by the catalog constructor.
	if got := s.Nodes(); len(got) != 2 {
		t.Errorf("Nodes() len = %d, want 2", len(got))
	}
}
