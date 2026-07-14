package authz

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// leafCert builds a parsed cert with the access-level extension for l.
func leafCert(t *testing.T, l Level) *x509.Certificate {
	t.Helper()
	value, _ := MarshalLevelValue(l)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(0x0abc),
		Subject:         pkix.Name{CommonName: "op@acme.example"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: accessLevelOID, Critical: false, Value: value}},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestClientCertMiddleware_SetsIdentity(t *testing.T) {
	var got Identity
	var ok bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/rpc", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafCert(t, LevelOperator)}}
	rec := httptest.NewRecorder()

	ClientCertMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !ok || got.Level != LevelOperator || got.CN != "op@acme.example" {
		t.Fatalf("identity = %+v ok=%v, want operator/op@acme.example", got, ok)
	}
	if got.Serial == "" {
		t.Error("serial is empty")
	}
}

func TestClientCertMiddleware_NoCert401(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rpc", nil) // req.TLS == nil
	ClientCertMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestClientCertMiddleware_MissingExtension403(t *testing.T) {
	// A verified peer cert that carries no access-level extension must be
	// rejected (403), never passed through or defaulted to a privileged level.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x0abc),
		Subject:      pkix.Name{CommonName: "op@acme.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rpc", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	ClientCertMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("next must not be called for a cert missing the access-level extension")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestBypassMiddleware_SetsDevIdentity(t *testing.T) {
	var got Identity
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got, _ = FromContext(r.Context()) })
	rec := httptest.NewRecorder()
	BypassMiddleware(next).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rpc", nil))
	if got.Level != LevelAdmin || got.CN != DevIdentity.CN {
		t.Fatalf("bypass identity = %+v, want DevIdentity", got)
	}
}
