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
	"sync"

	"github.com/CryptOS-PKI/manager/internal/store"
)

// Store is an in-memory, concurrency-safe store.Store backed by a fixed
// snapshot of nodes supplied at construction.
type Store struct {
	mu    sync.RWMutex
	nodes map[string]store.Node
}

// New builds a Store from the given nodes, keyed by Node.Name.
func New(nodes []store.Node) *Store {
	m := make(map[string]store.Node, len(nodes))
	for _, n := range nodes {
		m[n.Name] = n
	}

	return &Store{nodes: m}
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
