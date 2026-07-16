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

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// ListProfiles returns every certificate issuance profile known to the
// manager's store. This is a pure Store read; no node is dialed.
func (s *Service) ListProfiles(_ context.Context, _ *connect.Request[fleetv1.ListProfilesRequest]) (*connect.Response[fleetv1.ListProfilesResponse], error) {
	profiles := s.store.Profiles()
	items := make([]*fleetv1.CertProfile, len(profiles))
	for i, p := range profiles {
		items[i] = profileToProto(p)
	}

	return connect.NewResponse(&fleetv1.ListProfilesResponse{Items: items}), nil
}

// ListAdapters returns every enrollment protocol adapter known to the
// manager's store. This is a pure Store read; no node is dialed.
func (s *Service) ListAdapters(_ context.Context, _ *connect.Request[fleetv1.ListAdaptersRequest]) (*connect.Response[fleetv1.ListAdaptersResponse], error) {
	adapters := s.store.Adapters()
	items := make([]*fleetv1.EnrollmentAdapter, len(adapters))
	for i, a := range adapters {
		items[i] = adapterToProto(a)
	}

	return connect.NewResponse(&fleetv1.ListAdaptersResponse{Items: items}), nil
}

// ListAudit returns every audit event known to the manager's store. This
// is a pure Store read; no node is dialed.
func (s *Service) ListAudit(_ context.Context, _ *connect.Request[fleetv1.ListAuditRequest]) (*connect.Response[fleetv1.ListAuditResponse], error) {
	audit := s.store.Audit()
	items := make([]*fleetv1.AuditEvent, len(audit))
	for i, e := range audit {
		items[i] = auditToProto(e)
	}

	return connect.NewResponse(&fleetv1.ListAuditResponse{Items: items}), nil
}

// ListEnrollments returns every enrollment request known to the manager's
// store. This is a pure Store read; no node is dialed.
func (s *Service) ListEnrollments(_ context.Context, _ *connect.Request[fleetv1.ListEnrollmentsRequest]) (*connect.Response[fleetv1.ListEnrollmentsResponse], error) {
	enrollments := s.store.Enrollments()
	items := make([]*fleetv1.EnrollmentRequest, len(enrollments))
	for i, r := range enrollments {
		items[i] = enrollmentToProto(r)
	}

	return connect.NewResponse(&fleetv1.ListEnrollmentsResponse{Items: items}), nil
}

func profileToProto(p store.Profile) *fleetv1.CertProfile {
	return &fleetv1.CertProfile{
		Name:         p.Name,
		KeyAlg:       p.KeyAlg,
		KeyUsage:     p.KeyUsage,
		ExtKeyUsage:  p.ExtKeyUsage,
		IsCa:         p.IsCA,
		PathLen:      p.PathLen,
		Sans:         p.Sans,
		ValidityDays: p.ValidityDays,
	}
}

func adapterToProto(a store.Adapter) *fleetv1.EnrollmentAdapter {
	return &fleetv1.EnrollmentAdapter{
		Kind:        a.Kind,
		Name:        a.Name,
		Endpoint:    a.Endpoint,
		Profile:     a.Profile,
		Enabled:     a.Enabled,
		Challenges:  a.Challenges,
		GpoTemplate: a.GPOTemplate,
	}
}

func auditToProto(e store.AuditEvent) *fleetv1.AuditEvent {
	return &fleetv1.AuditEvent{
		Id:         e.ID,
		At:         e.At,
		Kind:       e.Kind,
		Summary:    e.Summary,
		TargetKind: e.TargetKind,
		TargetPath: e.TargetPath,
	}
}

func enrollmentToProto(r store.Enrollment) *fleetv1.EnrollmentRequest {
	return &fleetv1.EnrollmentRequest{
		Id:                 r.ID,
		ProposedName:       r.ProposedName,
		Role:               r.Role,
		ParentCn:           r.ParentCN,
		Address:            r.Address,
		Status:             r.Status,
		AttestationSummary: r.AttestationSummary,
		AttestationNodeId:  r.AttestationNodeID,
		CsrKeyType:         r.CSRKeyType,
		CsrSubjectCn:       r.CSRSubjectCN,
		RequestedAt:        r.RequestedAt,
		RejectionReason:    r.RejectionReason,
		AdmittedNodeName:   r.AdmittedNodeName,
		Kind:               r.Kind,
		PinnedKeySha256:    r.PinnedKeySHA256,
	}
}
