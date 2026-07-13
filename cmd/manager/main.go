// Command manager runs the CryptOS Fleet Manager Connect server: it dials
// the configured fleet nodes over mTLS and serves cryptos.fleet.v1.FleetService
// to the web UI.
package main

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
	"flag"
	"log"
	"net/http"

	connect "connectrpc.com/connect"
	fleetv1connect "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/config"
	"github.com/CryptOS-PKI/manager/internal/fleet"
	"github.com/CryptOS-PKI/manager/internal/nodeclient"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"github.com/CryptOS-PKI/manager/internal/store/seed"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the manager's YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("manager: %v", err)
	}

	nodes := make([]store.Node, len(cfg.Nodes))
	for i, n := range cfg.Nodes {
		nodes[i] = store.Node{
			Name:      n.Name,
			Endpoint:  n.Endpoint,
			Role:      n.Role,
			AdminCert: n.AdminCertPath,
			AdminKey:  n.AdminKeyPath,
			CACert:    n.CACertPath,
		}
	}
	profiles, adapters, audit, enrollments := seed.Catalog()
	st := memory.NewWithCatalog(nodes, profiles, adapters, audit, enrollments)

	dial := func(n store.Node) (fleet.NodeConn, error) {
		c, err := nodeclient.Dial(n)
		if err != nil {
			return nil, err
		}

		return c, nil
	}

	svc := fleet.New(st, dial)

	path, handler := fleetv1connect.NewFleetServiceHandler(svc, connect.WithInterceptors(authz.Bypass()))

	mux := http.NewServeMux()
	mux.Handle(path, handler)

	corsHandler := withCORS(cfg.CORSOrigins, mux)

	log.Printf("manager: listening on %s (h2c), %d node(s) configured, catalog seeded (%d profiles, %d adapters, %d audit events, %d enrollments)",
		cfg.Listen, len(nodes), len(profiles), len(adapters), len(audit), len(enrollments))

	server := &http.Server{
		Addr:    cfg.Listen,
		Handler: h2c.NewHandler(corsHandler, &http2.Server{}),
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("manager: serve: %v", err)
	}
}

// withCORS wraps next with a CORS handler that allows the given origins to
// call the Connect/gRPC-Web protocols: it permits POST/GET/OPTIONS, the
// headers Connect and gRPC-Web clients send, and exposes the gRPC status
// trailers so browser clients can read them.
func withCORS(origins []string, next http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		allowed[o] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if _, ok := allowed[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Expose-Headers", "Grpc-Status, Grpc-Message")
		}

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers",
				"Content-Type, Connect-Protocol-Version, Connect-Timeout-Ms, Grpc-Timeout, X-Grpc-Web, X-User-Agent")
			w.WriteHeader(http.StatusNoContent)

			return
		}

		next.ServeHTTP(w, r)
	})
}
