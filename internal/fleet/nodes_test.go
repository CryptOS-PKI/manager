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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

// fakeConn is a canned NodeConn used to drive Service without a real dial.
type fakeConn struct {
	status      *cryptosv1.GetStatusResponse
	identity    *cryptosv1.GetIdentityResponse
	issued      *cryptosv1.ListIssuedResponse
	revocations *cryptosv1.ListRevocationsResponse
	err         error
	closed      bool

	// attestKey, when set, makes Attest sign the nonce for real (mirroring
	// the node's CA-identity signer) instead of returning a zero response.
	attestKey *ecdsa.PrivateKey
	// attestBadSig makes Attest sign a digest that does NOT match the
	// nonce it was given, so verifyAttestation must reject the signature.
	attestBadSig bool
	// gotNonce records the nonce the fake received, so a test can assert
	// verifyAttestation actually sent one.
	gotNonce []byte

	// gotManagement records the Management the fake received via
	// SetManagement, so a test can assert what a LINK approval pushed.
	gotManagement *cryptosv1.Management
	// gotCSRProfile records the profile name SignSubordinateCSR was called
	// with, so a test can assert the ferry used the enrollment's profile.
	gotCSRProfile string
	// signSubordinateResp, when set, is returned by SignSubordinateCSR
	// instead of the zero-value response.
	signSubordinateResp *cryptosv1.SignSubordinateCSRResponse
	// calls records the ordered sequence of ferry-relevant method names
	// invoked on this fake, so a test can assert call order.
	calls *[]string
}

func (f *fakeConn) GetStatus(context.Context) (*cryptosv1.GetStatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.status, nil
}

func (f *fakeConn) GetIdentity(context.Context) (*cryptosv1.GetIdentityResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.identity, nil
}

func (f *fakeConn) ListIssued(context.Context) (*cryptosv1.ListIssuedResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.issued, nil
}

func (f *fakeConn) ListRevocations(context.Context) (*cryptosv1.ListRevocationsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.revocations, nil
}

func (f *fakeConn) Attest(_ context.Context, nonce []byte) (*cryptosv1.AttestResponse, error) {
	f.gotNonce = nonce
	if f.err != nil {
		return nil, f.err
	}
	if f.attestKey == nil {
		return &cryptosv1.AttestResponse{}, nil
	}
	signed := nonce
	if f.attestBadSig {
		// Sign different bytes than the nonce so the signature is valid
		// ASN.1 but does not verify against the nonce's digest.
		signed = append([]byte("wrong-bytes-"), nonce...)
	}
	digest := sha512.Sum384(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, f.attestKey, digest[:])
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&f.attestKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &cryptosv1.AttestResponse{
		Signature:      sig,
		IdentityPubDer: pubDER,
	}, nil
}

func (f *fakeConn) GetSubordinateCSR(context.Context) (*cryptosv1.GetSubordinateCSRResponse, error) {
	f.record("GetSubordinateCSR")
	if f.err != nil {
		return nil, f.err
	}
	return &cryptosv1.GetSubordinateCSRResponse{}, nil
}

func (f *fakeConn) SignSubordinateCSR(_ context.Context, _ []byte, profile string) (*cryptosv1.SignSubordinateCSRResponse, error) {
	f.record("SignSubordinateCSR")
	f.gotCSRProfile = profile
	if f.err != nil {
		return nil, f.err
	}
	if f.signSubordinateResp != nil {
		return f.signSubordinateResp, nil
	}
	return &cryptosv1.SignSubordinateCSRResponse{}, nil
}

func (f *fakeConn) SubmitSubordinateCertificate(context.Context, [][]byte, string) (*cryptosv1.SubmitSubordinateCertificateResponse, error) {
	f.record("SubmitSubordinateCertificate")
	if f.err != nil {
		return nil, f.err
	}
	return &cryptosv1.SubmitSubordinateCertificateResponse{}, nil
}

func (f *fakeConn) ApplyConfig(context.Context, *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &cryptosv1.ApplyConfigResponse{}, nil
}

func (f *fakeConn) SetManagement(_ context.Context, m *cryptosv1.Management) (*cryptosv1.SetManagementResponse, error) {
	f.gotManagement = m
	if f.err != nil {
		return nil, f.err
	}
	return &cryptosv1.SetManagementResponse{}, nil
}

// record appends name to the shared call log, if this fake was given one.
// Used by the SUBORDINATE ferry tests to assert child/parent call order.
func (f *fakeConn) record(name string) {
	if f.calls != nil {
		*f.calls = append(*f.calls, name)
	}
}

func (f *fakeConn) Close() error {
	f.closed = true
	return nil
}

func testStore() store.Store {
	return memory.New([]store.Node{
		{
			Name:     "A",
			Endpoint: "a.acme.com:4443",
			Role:     "root",
		},
		{
			Name:     "B",
			Endpoint: "b.acme.com:4444",
			Role:     "intermediate",
		},
	})
}

// dialFor returns a dial func that hands back conns keyed by node name, and
// records which conns it produced so a test can assert Close() was called.
func dialFor(conns map[string]*fakeConn) func(store.Node) (NodeConn, error) {
	return func(n store.Node) (NodeConn, error) {
		c, ok := conns[n.Name]
		if !ok {
			return nil, errors.New("dialFor: no fake conn for " + n.Name)
		}
		return c, nil
	}
}

func TestListNodes_PerNodeDegradation(t *testing.T) {
	connA := &fakeConn{
		status: &cryptosv1.GetStatusResponse{
			Status: &cryptosv1.NodeStatus{
				Role:          cryptosv1.NodeRole_NODE_ROLE_ROOT,
				IdentityState: cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED,
			},
		},
	}
	connB := &fakeConn{err: errors.New("dial refused")}

	svc := New(testStore(), dialFor(map[string]*fakeConn{"A": connA, "B": connB}))

	resp, err := svc.ListNodes(context.Background(), connect.NewRequest(&fleetv1.ListNodesRequest{}))
	if err != nil {
		t.Fatalf("ListNodes() error = %v, want nil", err)
	}

	nodes := resp.Msg.GetNodes()
	if len(nodes) != 2 {
		t.Fatalf("len(nodes) = %d, want 2", len(nodes))
	}

	byName := map[string]*fleetv1.NodeSummary{}
	for _, n := range nodes {
		byName[n.GetName()] = n
	}

	a := byName["A"]
	if a == nil {
		t.Fatal("missing summary for A")
	}
	if a.GetHealth() != fleetv1.Health_HEALTH_UP {
		t.Errorf("A.Health = %v, want HEALTH_UP", a.GetHealth())
	}
	if a.GetRole() != "root" {
		t.Errorf("A.Role = %q, want root", a.GetRole())
	}
	if a.GetIdentityState() != "ESTABLISHED" {
		t.Errorf("A.IdentityState = %q, want ESTABLISHED", a.GetIdentityState())
	}

	b := byName["B"]
	if b == nil {
		t.Fatal("missing summary for B")
	}
	if b.GetHealth() != fleetv1.Health_HEALTH_DOWN {
		t.Errorf("B.Health = %v, want HEALTH_DOWN", b.GetHealth())
	}
	if b.GetHealthDetail() == "" {
		t.Error("B.HealthDetail is empty, want the dial error text")
	}

	if !connA.closed {
		t.Error("connA was not closed")
	}
	if !connB.closed {
		t.Error("connB dial returned an error so there is no conn to close, but fake still shouldn't leak state")
	}
}

func TestGetNode_ReturnsDetailWithIdentity(t *testing.T) {
	connA := &fakeConn{
		status: &cryptosv1.GetStatusResponse{
			Status: &cryptosv1.NodeStatus{
				Role:          cryptosv1.NodeRole_NODE_ROLE_ROOT,
				IdentityState: cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED,
				TpmState:      cryptosv1.TpmState_TPM_STATE_OK,
				BootCount:     3,
			},
		},
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{
				ChainPem:   "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
				ChainDer:   [][]byte{[]byte("fake-der")},
				LeafSha256: []byte{0xde, 0xad, 0xbe, 0xef},
			},
		},
	}

	svc := New(testStore(), dialFor(map[string]*fakeConn{"A": connA}))

	resp, err := svc.GetNode(context.Background(), connect.NewRequest(&fleetv1.GetNodeRequest{Name: "A"}))
	if err != nil {
		t.Fatalf("GetNode(A) error = %v, want nil", err)
	}

	detail := resp.Msg.GetNode()
	if detail == nil {
		t.Fatal("GetNode(A) returned nil detail")
	}
	if detail.GetSummary().GetHealth() != fleetv1.Health_HEALTH_UP {
		t.Errorf("detail.Summary.Health = %v, want HEALTH_UP", detail.GetSummary().GetHealth())
	}
	if detail.GetIdentity().GetChainPem() != connA.identity.GetIdentity().GetChainPem() {
		t.Errorf("detail.Identity.ChainPem = %q, want %q", detail.GetIdentity().GetChainPem(), connA.identity.GetIdentity().GetChainPem())
	}
	if detail.GetTpmAvailable() != true {
		t.Error("detail.TpmAvailable = false, want true (TpmState = TPM_STATE_OK)")
	}
	if detail.GetBootCount() != 3 {
		t.Errorf("detail.BootCount = %d, want 3", detail.GetBootCount())
	}
}

// signCert builds a DER certificate for cn signed by the parent cert/key. When
// parent is nil the cert is self-signed (a root): it is signed with its own
// freshly generated key and its issuer is its own subject.
func signCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	signer, signerKey := parent, parentKey
	if signer == nil {
		signer, signerKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", cn, err)
	}
	return der, cert, key
}

func TestLeafCNs(t *testing.T) {
	rootDER, rootCert, rootKey := signCert(t, "ACME Root CA", nil, nil)
	interDER, _, _ := signCert(t, "ACME Intermediate CA", rootCert, rootKey)

	t.Run("self-signed root has issuer == cn", func(t *testing.T) {
		cn, issuer := leafCNs(&cryptosv1.Identity{ChainDer: [][]byte{rootDER}})
		if cn != "ACME Root CA" || issuer != "ACME Root CA" {
			t.Errorf("leafCNs(root) = (%q, %q), want (ACME Root CA, ACME Root CA)", cn, issuer)
		}
	})

	t.Run("subordinate issuer names the parent CA", func(t *testing.T) {
		cn, issuer := leafCNs(&cryptosv1.Identity{ChainDer: [][]byte{interDER, rootDER}})
		if cn != "ACME Intermediate CA" || issuer != "ACME Root CA" {
			t.Errorf("leafCNs(intermediate) = (%q, %q), want (ACME Intermediate CA, ACME Root CA)", cn, issuer)
		}
	})

	t.Run("nil identity yields empty", func(t *testing.T) {
		if cn, issuer := leafCNs(nil); cn != "" || issuer != "" {
			t.Errorf("leafCNs(nil) = (%q, %q), want empty", cn, issuer)
		}
	})

	t.Run("empty chain yields empty", func(t *testing.T) {
		if cn, issuer := leafCNs(&cryptosv1.Identity{}); cn != "" || issuer != "" {
			t.Errorf("leafCNs(empty) = (%q, %q), want empty", cn, issuer)
		}
	})

	t.Run("unparseable leaf yields empty", func(t *testing.T) {
		if cn, issuer := leafCNs(&cryptosv1.Identity{ChainDer: [][]byte{[]byte("not-a-cert")}}); cn != "" || issuer != "" {
			t.Errorf("leafCNs(garbage) = (%q, %q), want empty", cn, issuer)
		}
	})
}

func TestGetNode_NotFound(t *testing.T) {
	svc := New(testStore(), dialFor(map[string]*fakeConn{}))

	_, err := svc.GetNode(context.Background(), connect.NewRequest(&fleetv1.GetNodeRequest{Name: "missing"}))
	if err == nil {
		t.Fatal("GetNode(missing) error = nil, want NotFound")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("GetNode(missing) error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeNotFound {
		t.Errorf("GetNode(missing) error code = %v, want CodeNotFound", connectErr.Code())
	}
}
