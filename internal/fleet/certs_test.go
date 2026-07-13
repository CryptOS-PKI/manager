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
	"errors"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func certsTestStore() store.Store {
	return memory.New([]store.Node{
		{Name: "A", Endpoint: "a.acme.com:4443", Role: "root"},
		{Name: "B", Endpoint: "b.acme.com:4444", Role: "intermediate"},
	})
}

func TestListCertificates_MergesIssuedAndRevoked_SkipsBadNode(t *testing.T) {
	now := time.Now()

	connA := &fakeConn{
		issued: &cryptosv1.ListIssuedResponse{
			Issued: []*cryptosv1.IssuedCert{
				{
					SerialHex:   "01",
					SubjectDn:   "CN=leaf.acme.com",
					NotBefore:   timestamppb.New(now.Add(-time.Hour)),
					NotAfter:    timestamppb.New(now.Add(time.Hour)),
					ProfileName: "leaf-tls",
					IssuedAt:    timestamppb.New(now.Add(-time.Hour)),
				},
				{
					SerialHex:   "02",
					SubjectDn:   "CN=expired.acme.com",
					NotBefore:   timestamppb.New(now.Add(-48 * time.Hour)),
					NotAfter:    timestamppb.New(now.Add(-24 * time.Hour)),
					ProfileName: "leaf-tls",
					IssuedAt:    timestamppb.New(now.Add(-48 * time.Hour)),
				},
				{
					SerialHex:   "03",
					SubjectDn:   "CN=sub.acme.com",
					NotBefore:   timestamppb.New(now.Add(-time.Hour)),
					NotAfter:    timestamppb.New(now.Add(time.Hour)),
					ProfileName: "sub-ca",
					IssuedAt:    timestamppb.New(now.Add(-time.Hour)),
				},
			},
		},
		revocations: &cryptosv1.ListRevocationsResponse{
			Revocations: []*cryptosv1.Revocation{
				{
					SerialHex:  "01",
					RevokedAt:  timestamppb.New(now.Add(-time.Minute)),
					ReasonCode: 1,
				},
			},
		},
	}
	connB := &fakeConn{err: errors.New("dial refused")}

	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA, "B": connB}))

	resp, err := svc.ListCertificates(context.Background(), connect.NewRequest(&fleetv1.ListCertificatesRequest{}))
	if err != nil {
		t.Fatalf("ListCertificates() error = %v, want nil", err)
	}

	certs := resp.Msg.GetCertificates()
	if len(certs) != 3 {
		t.Fatalf("len(certs) = %d, want 3 (node B skipped, not fatal)", len(certs))
	}

	bySerial := map[string]*fleetv1.Certificate{}
	for _, c := range certs {
		if c.GetIssuerNode() != "A" {
			t.Errorf("cert %s IssuerNode = %q, want A", c.GetSerial(), c.GetIssuerNode())
		}
		bySerial[c.GetSerial()] = c
	}

	revoked := bySerial["01"]
	if revoked == nil {
		t.Fatal("missing serial 01")
	}
	if revoked.GetStatus() != "REVOKED" {
		t.Errorf("serial 01 Status = %q, want REVOKED", revoked.GetStatus())
	}
	if revoked.GetRevokedAt() == "" {
		t.Error("serial 01 RevokedAt is empty, want RFC3339 timestamp")
	}
	if revoked.GetKind() != "leaf" {
		t.Errorf("serial 01 Kind = %q, want leaf", revoked.GetKind())
	}

	expired := bySerial["02"]
	if expired == nil {
		t.Fatal("missing serial 02")
	}
	if expired.GetStatus() != "EXPIRED" {
		t.Errorf("serial 02 Status = %q, want EXPIRED", expired.GetStatus())
	}
	if expired.GetKind() != "leaf" {
		t.Errorf("serial 02 Kind = %q, want leaf", expired.GetKind())
	}

	subCA := bySerial["03"]
	if subCA == nil {
		t.Fatal("missing serial 03")
	}
	if subCA.GetStatus() != "VALID" {
		t.Errorf("serial 03 Status = %q, want VALID", subCA.GetStatus())
	}
	if subCA.GetKind() != "subordinate-ca" {
		t.Errorf("serial 03 Kind = %q, want subordinate-ca", subCA.GetKind())
	}
	if subCA.GetSubjectCn() != "CN=sub.acme.com" {
		t.Errorf("serial 03 SubjectCn = %q, want CN=sub.acme.com", subCA.GetSubjectCn())
	}
}

func TestListCertificates_ScopedToOneNode(t *testing.T) {
	connA := &fakeConn{
		issued: &cryptosv1.ListIssuedResponse{
			Issued: []*cryptosv1.IssuedCert{
				{SerialHex: "01", NotBefore: timestamppb.Now(), NotAfter: timestamppb.New(time.Now().Add(time.Hour))},
			},
		},
	}

	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	resp, err := svc.ListCertificates(context.Background(), connect.NewRequest(&fleetv1.ListCertificatesRequest{Node: "A"}))
	if err != nil {
		t.Fatalf("ListCertificates(node=A) error = %v, want nil", err)
	}

	certs := resp.Msg.GetCertificates()
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if certs[0].GetIssuerNode() != "A" {
		t.Errorf("IssuerNode = %q, want A", certs[0].GetIssuerNode())
	}
}

func TestListCertificates_ScopedToUnknownNode_NotFound(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{}))

	_, err := svc.ListCertificates(context.Background(), connect.NewRequest(&fleetv1.ListCertificatesRequest{Node: "missing"}))
	if err == nil {
		t.Fatal("ListCertificates(node=missing) error = nil, want NotFound")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("ListCertificates(node=missing) error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeNotFound {
		t.Errorf("ListCertificates(node=missing) error code = %v, want CodeNotFound", connectErr.Code())
	}
}
