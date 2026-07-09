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

// Store is the manager's read access to the fleet inventory.
type Store interface {
	// Nodes returns every node in the inventory.
	Nodes() []Node
	// Node returns the node with the given name, and whether it was found.
	Node(name string) (Node, bool)
}
