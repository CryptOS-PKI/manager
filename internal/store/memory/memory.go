// Package memory implements store.Store as an in-process, read-mostly map
// keyed by node name.
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
	"fmt"
	"sync"

	"github.com/CryptOS-PKI/manager/internal/store"
)

// Store is an in-memory, concurrency-safe store.Store backed by a fixed
// snapshot of nodes and catalog data supplied at construction.
type Store struct {
	mu          sync.RWMutex
	nodes       map[string]store.Node
	profiles    []store.Profile
	adapters    []store.Adapter
	audit       []store.AuditEvent
	enrollments []store.Enrollment
}

// New builds a Store from the given nodes, keyed by Node.Name, with an
// empty catalog. Use NewWithCatalog to also seed profiles/adapters/audit/
// enrollments.
func New(nodes []store.Node) *Store {
	return NewWithCatalog(nodes, nil, nil, nil, nil)
}

// NewWithCatalog builds a Store from the given nodes, keyed by Node.Name,
// and the given catalog data.
func NewWithCatalog(nodes []store.Node, profiles []store.Profile, adapters []store.Adapter, audit []store.AuditEvent, enrollments []store.Enrollment) *Store {
	m := make(map[string]store.Node, len(nodes))
	for _, n := range nodes {
		m[n.Name] = n
	}

	return &Store{
		nodes:       m,
		profiles:    profiles,
		adapters:    adapters,
		audit:       audit,
		enrollments: enrollments,
	}
}

// Nodes returns every node in the store.
func (s *Store) Nodes() []store.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}

	return out
}

// Node returns the node with the given name, and whether it was found.
func (s *Store) Node(name string) (store.Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n, ok := s.nodes[name]

	return n, ok
}

// Profiles returns every certificate issuance profile.
func (s *Store) Profiles() []store.Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.Profile, len(s.profiles))
	copy(out, s.profiles)

	return out
}

// Adapters returns every enrollment protocol adapter.
func (s *Store) Adapters() []store.Adapter {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.Adapter, len(s.adapters))
	copy(out, s.adapters)

	return out
}

// Audit returns every audit event.
func (s *Store) Audit() []store.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.AuditEvent, len(s.audit))
	copy(out, s.audit)

	return out
}

// AddAuditEvent appends e to the hash-chained audit log: PrevHash is the last
// event's Hash (empty for the first), Hash is computed over the chain, and the
// stored event is returned.
func (s *Store) AddAuditEvent(e store.AuditEvent) store.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	var prev string
	if n := len(s.audit); n > 0 {
		prev = s.audit[n-1].Hash
	}
	e.PrevHash = prev
	e.Hash = store.HashEvent(prev, e)
	s.audit = append(s.audit, e)

	return e
}

// Enrollments returns every enrollment request.
func (s *Store) Enrollments() []store.Enrollment {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.Enrollment, len(s.enrollments))
	copy(out, s.enrollments)

	return out
}

// AddEnrollment appends a new enrollment request.
func (s *Store) AddEnrollment(e store.Enrollment) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.enrollments = append(s.enrollments, e)
}

// Enrollment returns the enrollment request with the given ID, and whether
// it was found.
func (s *Store) Enrollment(id string) (store.Enrollment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, e := range s.enrollments {
		if e.ID == id {
			return e, true
		}
	}

	return store.Enrollment{}, false
}

// UpdateEnrollment applies mutate to the enrollment with the given ID. It
// returns an error if no enrollment has that ID.
func (s *Store) UpdateEnrollment(id string, mutate func(*store.Enrollment)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.enrollments {
		if s.enrollments[i].ID == id {
			mutate(&s.enrollments[i])
			return nil
		}
	}

	return fmt.Errorf("memory: enrollment %q not found", id)
}
