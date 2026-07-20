// Package fleet implements the manager's cryptos.fleet.v1.FleetService
// Connect handler: it fans out to each fleet node over nodeclient and
// reports per-node health without failing the whole request when one node
// is unreachable.
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

	fleetv1connect "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1/fleetv1connect"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// NodeConn is the manager's-eye view of a per-node connection: just enough
// to serve FleetService. nodeclient.Client satisfies it; tests inject a
// fake instead of dialing a real node.
type NodeConn interface {
	GetStatus(ctx context.Context) (*cryptosv1.GetStatusResponse, error)
	GetIdentity(ctx context.Context) (*cryptosv1.GetIdentityResponse, error)
	ListIssued(ctx context.Context) (*cryptosv1.ListIssuedResponse, error)
	ListRevocations(ctx context.Context) (*cryptosv1.ListRevocationsResponse, error)
	Attest(ctx context.Context, nonce []byte) (*cryptosv1.AttestResponse, error)
	GetSubordinateCSR(ctx context.Context) (*cryptosv1.GetSubordinateCSRResponse, error)
	SignSubordinateCSR(ctx context.Context, csrDER []byte, profile string) (*cryptosv1.SignSubordinateCSRResponse, error)
	SubmitSubordinateCertificate(ctx context.Context, chainDER [][]byte, chainPEM string) (*cryptosv1.SubmitSubordinateCertificateResponse, error)
	ApplyConfig(ctx context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error)
	GetConfig(ctx context.Context) (*cryptosv1.GetConfigResponse, error)
	SetManagement(ctx context.Context, m *cryptosv1.Management) (*cryptosv1.SetManagementResponse, error)
	RevokeCertificate(ctx context.Context, serialHex string, reasonCode int32) (*cryptosv1.RevokeCertificateResponse, error)
	IssueLeaf(ctx context.Context, csrDER []byte, profileName string) (*cryptosv1.IssueLeafResponse, error)
	BeginKeyRotation(ctx context.Context) (*cryptosv1.BeginKeyRotationResponse, error)
	CompleteKeyRotation(ctx context.Context, chainDER [][]byte, chainPEM string) (*cryptosv1.CompleteKeyRotationResponse, error)
	Close() error
}

// Service implements fleetv1connect.FleetServiceHandler over a fleet
// inventory Store, dialing each node on demand via dial.
type Service struct {
	store store.Store
	dial  func(store.Node) (NodeConn, error)

	dialPEM       func(endpoint, certPEM, keyPEM, caPEM string) (NodeConn, error)
	operatorCAPEM string
}

// New builds a Service backed by st, dialing nodes with dial. Callers in
// production pass an adapter over nodeclient.Dial; tests pass a fake.
func New(st store.Store, dial func(store.Node) (NodeConn, error)) *Service {
	return &Service{store: st, dial: dial}
}

// WithEnrollment supplies the PEM dial seam (for LINK, which reaches a
// not-yet-inventoried node) and the operator CA PEM (stamped into a linked
// node's managed-state trust anchor). Returns s for chaining.
func (s *Service) WithEnrollment(dialPEM func(endpoint, certPEM, keyPEM, caPEM string) (NodeConn, error), operatorCAPEM string) *Service {
	s.dialPEM = dialPEM
	s.operatorCAPEM = operatorCAPEM

	return s
}

var _ fleetv1connect.FleetServiceHandler = (*Service)(nil)
