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
	"math/big"
	"net/http"
	"strings"
)

// ClientCertMiddleware extracts the operator identity from the verified TLS
// peer certificate and puts it on the request context. The TLS layer
// (RequireAndVerifyClientCert + operator CA) guarantees any presented cert is
// trusted; this only reads it. A request with no peer cert is 401; a cert
// without the access-level extension is 403.
func ClientCertMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		level, err := LevelFromCertificate(cert)
		if err != nil {
			http.Error(w, "operator certificate missing access level", http.StatusForbidden)
			return
		}
		id := Identity{CN: cert.Subject.CommonName, Serial: formatSerial(cert.SerialNumber), Level: level}
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), id)))
	})
}

// BypassMiddleware injects DevIdentity, for the AuthBypass dev path where the
// browser talks h2c and presents no client cert.
func BypassMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), DevIdentity)))
	})
}

// formatSerial renders a certificate serial as colon-separated uppercase hex.
func formatSerial(n *big.Int) string {
	b := n.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	parts := make([]string, len(b))
	const hexdigits = "0123456789ABCDEF"
	for i, by := range b {
		parts[i] = string([]byte{hexdigits[by>>4], hexdigits[by&0x0f]})
	}
	return strings.Join(parts, ":")
}
