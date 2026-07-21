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

import (
	"crypto/sha256"
	"encoding/hex"
)

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

// Profile is a catalog certificate-issuance template, stored as the marshaled
// cryptos.v1.CertificateProfile so it is a lossless superset the node accepts
// verbatim. Name is the catalog identity key; Spec is the marshaled proto.
type Profile struct {
	Name string
	Spec []byte // marshaled cryptos.v1.CertificateProfile
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
// cryptos.fleet.v1.AuditEvent. PrevHash and Hash back a tamper-evident hash
// chain over the append-ordered log (see HashEvent).
type AuditEvent struct {
	ID         string
	At         string
	Kind       string
	Summary    string
	TargetKind string
	TargetPath string
	PrevHash   string
	Hash       string
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
	Kind               string // LINK|SUBORDINATE
	PinnedKeySHA256    string // TOFU-pinned node identity (SPKI SHA-256 hex)
	AttestationOK      bool
	Profile            string // SUBORDINATE: issuing profile name (store-internal; no proto field)
}

// OperatorCredential is one operator client certificate the manager issued via
// the operator-CA node. It is the durable record backing the Operators admin
// surface: the manager never holds the operator's private key (browser-held),
// only this metadata. It mirrors cryptos.fleet.v1.OperatorCredential.
type OperatorCredential struct {
	CommonName string
	SerialHex  string
	Level      string
	NotAfter   string
	Revoked    bool
}

// Store is the manager's read access to the fleet inventory and its
// manager-owned catalog data (profiles, adapters, audit, enrollments,
// operator credentials).
type Store interface {
	// Nodes returns every node in the inventory.
	Nodes() []Node
	// Node returns the node with the given name, and whether it was found.
	Node(name string) (Node, bool)
	// AddNode inserts n into the inventory, replacing any node with the same
	// name. It is how an adopted node joins the fleet.
	AddNode(n Node)
	// Profiles returns every certificate issuance profile.
	Profiles() []Profile
	// Profile returns the profile with the given name, and whether it was
	// found.
	Profile(name string) (Profile, bool)
	// CreateProfile adds p to the catalog. It errors if a profile with the
	// same name already exists.
	CreateProfile(p Profile) error
	// UpdateProfile replaces the profile with p.Name. It errors if no
	// profile has that name.
	UpdateProfile(p Profile) error
	// DeleteProfile removes the profile with the given name. It errors if no
	// profile has that name.
	DeleteProfile(name string) error
	// Adapters returns every enrollment protocol adapter.
	Adapters() []Adapter
	// SetAdapterEnabled sets the enabled state of the adapter with the given
	// name and returns the updated adapter. It errors if no adapter has that
	// name.
	SetAdapterEnabled(name string, enabled bool) (Adapter, error)
	// Audit returns every audit event, in append order.
	Audit() []AuditEvent
	// AddAuditEvent appends e to the hash chain: it sets PrevHash to the
	// previous event's Hash (empty for the first), computes Hash, persists
	// the event, and returns the stored copy.
	AddAuditEvent(e AuditEvent) AuditEvent
	// Enrollments returns every enrollment request.
	Enrollments() []Enrollment
	// AddEnrollment appends a new enrollment request.
	AddEnrollment(e Enrollment)
	// UpdateEnrollment applies mutate to the enrollment with the given ID.
	// It returns an error if no enrollment has that ID.
	UpdateEnrollment(id string, mutate func(*Enrollment)) error
	// Enrollment returns the enrollment request with the given ID, and
	// whether it was found.
	Enrollment(id string) (Enrollment, bool)
	// OperatorCredentials returns every issued operator credential, in a
	// stable order.
	OperatorCredentials() []OperatorCredential
	// AddOperatorCredential records a newly issued operator credential.
	AddOperatorCredential(c OperatorCredential)
	// MarkOperatorCredentialRevoked flags the credential with the given hex
	// serial as revoked. It returns an error if no credential has that serial.
	MarkOperatorCredentialRevoked(serialHex string) error
}

// HashEvent computes the chain hash for an audit event: the SHA-256, in hex, of
// the previous event's hash and the event's immutable fields. Chaining prevHash
// into each hash makes the log tamper-evident: altering any past event breaks
// every hash after it. The identity/derived fields (PrevHash, Hash) are not
// themselves hashed.
func HashEvent(prevHash string, e AuditEvent) string {
	h := sha256.Sum256([]byte(prevHash + "\n" + e.ID + e.At + e.Kind + e.Summary + e.TargetKind + e.TargetPath))
	return hex.EncodeToString(h[:])
}
