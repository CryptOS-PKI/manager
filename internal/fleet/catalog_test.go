package fleet

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
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"github.com/CryptOS-PKI/manager/internal/store/seed"
)

func catalogTestStore() store.Store {
	profiles, adapters, audit, enrollments := seed.Catalog()
	return memory.NewWithCatalog(nil, profiles, adapters, audit, enrollments)
}

func TestListProfiles_ReturnsSeededRows(t *testing.T) {
	svc := New(catalogTestStore(), nil)

	resp, err := svc.ListProfiles(context.Background(), connect.NewRequest(&fleetv1.ListProfilesRequest{}))
	if err != nil {
		t.Fatalf("ListProfiles() error = %v, want nil", err)
	}

	items := resp.Msg.GetItems()
	if len(items) == 0 {
		t.Fatal("ListProfiles() returned no items, want seeded profiles")
	}

	var found bool
	for _, p := range items {
		if p.GetName() == "TLS Server (LDAPS)" {
			found = true
			if p.GetKeyAlg() != "ECDSA-P384" {
				t.Errorf("profile KeyAlg = %q, want ECDSA-P384", p.GetKeyAlg())
			}
			if p.GetIsCa() {
				t.Error("TLS Server (LDAPS) IsCa = true, want false")
			}
		}
	}
	if !found {
		t.Error(`ListProfiles() missing "TLS Server (LDAPS)"`)
	}
}

func TestListAdapters_ReturnsAllFourProtocols(t *testing.T) {
	svc := New(catalogTestStore(), nil)

	resp, err := svc.ListAdapters(context.Background(), connect.NewRequest(&fleetv1.ListAdaptersRequest{}))
	if err != nil {
		t.Fatalf("ListAdapters() error = %v, want nil", err)
	}

	items := resp.Msg.GetItems()
	byKind := make(map[string]*fleetv1.EnrollmentAdapter, len(items))
	for _, a := range items {
		byKind[a.GetKind()] = a
	}

	for _, kind := range []string{"acme", "est", "scep", "ms-autoenroll"} {
		if _, ok := byKind[kind]; !ok {
			t.Errorf("ListAdapters() missing kind %q", kind)
		}
	}

	acme := byKind["acme"]
	if acme != nil {
		if !acme.GetEnabled() {
			t.Error("acme adapter Enabled = false, want true")
		}
		if acme.GetEndpoint() == "" {
			t.Error("acme adapter Endpoint is empty")
		}
		if acme.GetProfile() == "" {
			t.Error("acme adapter Profile is empty")
		}
	}
}

func TestListAudit_ReturnsSeededEvents(t *testing.T) {
	svc := New(catalogTestStore(), nil)

	resp, err := svc.ListAudit(context.Background(), connect.NewRequest(&fleetv1.ListAuditRequest{}))
	if err != nil {
		t.Fatalf("ListAudit() error = %v, want nil", err)
	}

	items := resp.Msg.GetItems()
	if len(items) < 6 {
		t.Fatalf("ListAudit() returned %d items, want at least 6", len(items))
	}

	var found bool
	for _, e := range items {
		if e.GetId() == "aud-0000" {
			found = true
			if e.GetKind() != "issued" {
				t.Errorf("aud-0000 Kind = %q, want issued", e.GetKind())
			}
		}
	}
	if !found {
		t.Error(`ListAudit() missing "aud-0000"`)
	}
}

func TestListEnrollments_ReturnsAtLeastOnePending(t *testing.T) {
	svc := New(catalogTestStore(), nil)

	resp, err := svc.ListEnrollments(context.Background(), connect.NewRequest(&fleetv1.ListEnrollmentsRequest{}))
	if err != nil {
		t.Fatalf("ListEnrollments() error = %v, want nil", err)
	}

	items := resp.Msg.GetItems()
	if len(items) == 0 {
		t.Fatal("ListEnrollments() returned no items, want seeded enrollments")
	}

	var pending int
	for _, r := range items {
		if r.GetStatus() == "PENDING" {
			pending++
		}
	}
	if pending == 0 {
		t.Error("ListEnrollments() has no PENDING requests, want at least 1")
	}
}
