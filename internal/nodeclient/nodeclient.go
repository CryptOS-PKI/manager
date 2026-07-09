// Package nodeclient dials a fleet node's mTLS gRPC endpoint and wraps the
// generated NodeService client with the manager's admin-cert-only trust
// model.
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
	"crypto/tls"
	"fmt"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client is a per-node mTLS gRPC connection to a fleet node's NodeService.
type Client struct {
	conn *grpc.ClientConn
	node cryptosv1.NodeServiceClient
}

// Dial opens a gRPC connection to node's endpoint, presenting node's admin
// client certificate for mTLS.
//
// The node's server certificate is ephemeral and self-signed per boot, so it
// cannot be verified against a pinned CA or hostname/SAN. Dial therefore
// relaxes server verification (InsecureSkipVerify) while still presenting
// the admin client certificate, which is the credential the node actually
// enforces via client authentication. Server-identity pinning is future
// hardening, not this dev slice.
func Dial(node store.Node) (*Client, error) {
	adminCert, err := tls.LoadX509KeyPair(node.AdminCert, node.AdminKey)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: load admin cert/key for %s: %w", node.Name, err)
	}

	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{adminCert},
		InsecureSkipVerify: true, //nolint:gosec // node's server cert is ephemeral self-signed; client-cert auth is the trust boundary here.
	}

	conn, err := grpc.NewClient(node.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("nodeclient: dial %s (%s): %w", node.Name, node.Endpoint, err)
	}

	return &Client{
		conn: conn,
		node: cryptosv1.NewNodeServiceClient(conn),
	}, nil
}

// GetStatus returns the node's current status.
func (c *Client) GetStatus(ctx context.Context) (*cryptosv1.GetStatusResponse, error) {
	return c.node.GetStatus(ctx, &cryptosv1.GetStatusRequest{})
}

// GetIdentity returns the node's current certificate identity.
func (c *Client) GetIdentity(ctx context.Context) (*cryptosv1.GetIdentityResponse, error) {
	return c.node.GetIdentity(ctx, &cryptosv1.GetIdentityRequest{})
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
