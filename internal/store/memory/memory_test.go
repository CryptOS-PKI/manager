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
