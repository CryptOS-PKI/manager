package nodeclient

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// fakeNodeService is a minimal NodeService that answers GetStatus and
// GetIdentity with canned, distinctive responses.
type fakeNodeService struct {
	cryptosv1.UnimplementedNodeServiceServer
}

func (fakeNodeService) GetStatus(context.Context, *cryptosv1.GetStatusRequest) (*cryptosv1.GetStatusResponse, error) {
	return &cryptosv1.GetStatusResponse{
		Status: &cryptosv1.NodeStatus{
			SoftwareVersion: "fake-node-v0.0.1-test-marker",
		},
	}, nil
}

func (fakeNodeService) GetIdentity(context.Context, *cryptosv1.GetIdentityRequest) (*cryptosv1.GetIdentityResponse, error) {
	return &cryptosv1.GetIdentityResponse{
		Identity: &cryptosv1.Identity{
			ChainPem: "-----BEGIN CERTIFICATE-----\nfake-identity-test-marker\n-----END CERTIFICATE-----\n",
		},
	}, nil
}

// testCA is a minimal self-signed CA used to mint both the fake node's
// server cert and the test admin client cert.
type testCA struct {
	cert    *x509.Certificate
	certDER []byte
	key     *rsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	return &testCA{cert: cert, certDER: der, key: key}
}

// issueLeaf mints a leaf certificate signed by the CA for the given common
// name, suitable for either server or client use.
func (ca *testCA) issueLeaf(t *testing.T, cn string, extKeyUsage []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  extKeyUsage,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build tls.Certificate: %v", err)
	}

	return pair
}

func (ca *testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	return pool
}

// writePEMFiles writes the cert+key of pair to PEM files under dir and
// returns their paths.
func writePEMFiles(t *testing.T, dir string, pair tls.Certificate) (certPath, keyPath string) {
	t.Helper()

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})

	key, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("private key is not RSA")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	certPath = filepath.Join(dir, "admin.crt")
	keyPath = filepath.Join(dir, "admin.key")

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certPath, keyPath
}

// startFakeNode starts a fake NodeService over TLS that requires and
// verifies a client cert signed by clientCA. It returns the listen address
// and a stop function.
func startFakeNode(t *testing.T, serverCA *testCA, clientCA *testCA) (addr string, stop func()) {
	t.Helper()

	serverPair := serverCA.issueLeaf(t, "fake-node", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA.pool(),
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	cryptosv1.RegisterNodeServiceServer(srv, fakeNodeService{})

	go func() {
		_ = srv.Serve(lis)
	}()

	addr = lis.Addr().String()
	stop = func() {
		srv.Stop()
	}

	return addr, stop
}

func TestDial_GetStatus_GetIdentity(t *testing.T) {
	serverCA := newTestCA(t, "fake-node-server-ca")
	clientCA := newTestCA(t, "fake-node-client-ca")

	addr, stop := startFakeNode(t, serverCA, clientCA)
	defer stop()

	adminPair := clientCA.issueLeaf(t, "manager-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	certPath, keyPath := writePEMFiles(t, t.TempDir(), adminPair)

	node := store.Node{
		Name:      "fake-node",
		Endpoint:  addr,
		Role:      "root",
		AdminCert: certPath,
		AdminKey:  keyPath,
		// The node's server cert is ephemeral self-signed in real deployments,
		// so Dial does not pin/verify a server CA; CACert is left empty here
		// to reflect that Dial must not depend on it.
		CACert: "",
	}

	client, err := Dial(node)
	if err != nil {
		t.Fatalf("Dial() error = %v, want nil", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	statusResp, err := client.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus() error = %v, want nil", err)
	}
	if got := statusResp.GetStatus().GetSoftwareVersion(); got != "fake-node-v0.0.1-test-marker" {
		t.Errorf("GetStatus().Status.SoftwareVersion = %q, want fake-node-v0.0.1-test-marker", got)
	}

	identityResp, err := client.GetIdentity(ctx)
	if err != nil {
		t.Fatalf("GetIdentity() error = %v, want nil", err)
	}
	wantChain := "-----BEGIN CERTIFICATE-----\nfake-identity-test-marker\n-----END CERTIFICATE-----\n"
	if got := identityResp.GetIdentity().GetChainPem(); got != wantChain {
		t.Errorf("GetIdentity().Identity.ChainPem = %q, want %q", got, wantChain)
	}
}

func TestDial_BadCertPath(t *testing.T) {
	node := store.Node{
		Name:      "broken-node",
		Endpoint:  "127.0.0.1:0",
		Role:      "root",
		AdminCert: "/nonexistent/admin.crt",
		AdminKey:  "/nonexistent/admin.key",
		CACert:    "/nonexistent/ca.pem",
	}

	_, err := Dial(node)
	if err == nil {
		t.Fatal("Dial() error = nil, want non-nil for missing cert/key files")
	}
}

func TestClient_GetStatus_NotListening(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	adminPair := clientCA.issueLeaf(t, "manager-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	certPath, keyPath := writePEMFiles(t, t.TempDir(), adminPair)

	node := store.Node{
		Name:      "unreachable-node",
		Endpoint:  "127.0.0.1:1",
		Role:      "root",
		AdminCert: certPath,
		AdminKey:  keyPath,
		CACert:    "",
	}

	client, err := Dial(node)
	if err != nil {
		t.Fatalf("Dial() error = %v, want nil (dial is lazy)", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.GetStatus(ctx); err == nil {
		t.Fatal("GetStatus() error = nil, want non-nil for a node that is not listening")
	}
}
