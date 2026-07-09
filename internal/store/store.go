// Package store defines the manager's view of the fleet inventory.
package store

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

// Node is one fleet member as seen by the store: its dial address, role,
// and the file paths for its admin mTLS client cert/key and pinned CA.
type Node struct {
	Name      string
	Endpoint  string
	Role      string
	AdminCert string
	AdminKey  string
	CACert    string
}

// Profile is a reusable certificate issuance template: key algorithm, usage
// extensions, and validity. It mirrors cryptos.fleet.v1.CertProfile.
type Profile struct {
	Name         string
	KeyAlg       string
	KeyUsage     []string
	ExtKeyUsage  []string
	IsCA         bool
	PathLen      int32
	Sans         []string
	ValidityDays int32
}

// Adapter is an enrollment protocol adapter's configuration: which protocol
// it speaks, where it listens, and which Profile it issues against. It
// mirrors cryptos.fleet.v1.EnrollmentAdapter.
type Adapter struct {
	Kind        string
	Name        string
	Endpoint    string
	Profile     string
	Enabled     bool
	Challenges  []string
	GPOTemplate string
}

// AuditEvent is one manager-observed audit record. It mirrors
// cryptos.fleet.v1.AuditEvent.
type AuditEvent struct {
	ID         string
	At         string
	Kind       string
	Summary    string
	TargetKind string
	TargetPath string
}

// Enrollment is a node's request to join the fleet under a parent CA,
// pending admin approval. It mirrors cryptos.fleet.v1.EnrollmentRequest.
type Enrollment struct {
	ID                 string
	ProposedName       string
	Role               string
	ParentCN           string
	Address            string
	Status             string
	AttestationSummary string
	AttestationNodeID  string
	CSRKeyType         string
	CSRSubjectCN       string
	RequestedAt        string
	RejectionReason    string
	AdmittedNodeName   string
}

// Store is the manager's read access to the fleet inventory and its
// manager-owned catalog data (profiles, adapters, audit, enrollments).
type Store interface {
	// Nodes returns every node in the inventory.
	Nodes() []Node
	// Node returns the node with the given name, and whether it was found.
	Node(name string) (Node, bool)
	// Profiles returns every certificate issuance profile.
	Profiles() []Profile
	// Adapters returns every enrollment protocol adapter.
	Adapters() []Adapter
	// Audit returns every audit event.
	Audit() []AuditEvent
	// Enrollments returns every enrollment request.
	Enrollments() []Enrollment
}
