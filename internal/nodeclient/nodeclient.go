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

// DialPEM dials a node presenting the given admin client cert/key (PEM), for
// operator-initiated enrollment where the material is supplied at request
// time rather than from the node inventory. Server verification is relaxed
// (the node enforces client-auth); caPEM is accepted for future server
// pinning.
func DialPEM(endpoint, certPEM, keyPEM, caPEM string) (*Client, error) {
	adminCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("nodeclient: parse admin cert/key PEM: %w", err)
	}

	_ = caPEM // reserved for future server-cert pinning (Dial also relaxes server verify today)

	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{adminCert},
		InsecureSkipVerify: true, //nolint:gosec // node's server cert is ephemeral self-signed; client-cert auth is the trust boundary here.
	}

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("nodeclient: dial %s: %w", endpoint, err)
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

// ListIssued returns the certificates this node has issued.
func (c *Client) ListIssued(ctx context.Context) (*cryptosv1.ListIssuedResponse, error) {
	return c.node.ListIssued(ctx, &cryptosv1.ListIssuedRequest{})
}

// ListRevocations returns this node's revoked certificates.
func (c *Client) ListRevocations(ctx context.Context) (*cryptosv1.ListRevocationsResponse, error) {
	return c.node.ListRevocations(ctx, &cryptosv1.ListRevocationsRequest{})
}

// Attest asks the node to sign nonce with its identity key, proving
// possession of the private key behind its current certificate.
func (c *Client) Attest(ctx context.Context, nonce []byte) (*cryptosv1.AttestResponse, error) {
	return c.node.Attest(ctx, &cryptosv1.AttestRequest{Nonce: nonce})
}

// GetSubordinateCSR returns the node's own DER-encoded PKCS#10 CSR, generated
// when it is provisioning as a subordinate awaiting a parent's signature.
func (c *Client) GetSubordinateCSR(ctx context.Context) (*cryptosv1.GetSubordinateCSRResponse, error) {
	return c.node.GetSubordinateCSR(ctx, &cryptosv1.GetSubordinateCSRRequest{})
}

// SignSubordinateCSR asks a parent node to sign a child's DER CSR under the
// named certificate profile (which sets CA:TRUE + pathLen), returning the
// signed cert and full issuing chain.
func (c *Client) SignSubordinateCSR(ctx context.Context, csrDER []byte, profile string) (*cryptosv1.SignSubordinateCSRResponse, error) {
	return c.node.SignSubordinateCSR(ctx, &cryptosv1.SignSubordinateCSRRequest{
		CsrDer:      csrDER,
		ProfileName: profile,
	})
}

// SubmitSubordinateCertificate delivers a parent-signed chain (leaf-first:
// this node's cert, parent, ..., root) back to the subordinate node so it
// can adopt its new identity.
func (c *Client) SubmitSubordinateCertificate(ctx context.Context, chainDER [][]byte, chainPEM string) (*cryptosv1.SubmitSubordinateCertificateResponse, error) {
	return c.node.SubmitSubordinateCertificate(ctx, &cryptosv1.SubmitSubordinateCertificateRequest{
		ChainDer: chainDER,
		ChainPem: chainPEM,
	})
}

// ApplyConfig pushes a machine configuration to the node.
func (c *Client) ApplyConfig(ctx context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	return c.node.ApplyConfig(ctx, &cryptosv1.ApplyConfigRequest{Config: cfg})
}

// SetManagement merges Fleet-Manager managed-state into the node's persisted
// config: it marks the node as managed by this operator CN, adds the
// operator CA as a trusted client CA, and optionally makes the node's own
// operator surface read-only.
func (c *Client) SetManagement(ctx context.Context, m *cryptosv1.Management) (*cryptosv1.SetManagementResponse, error) {
	return c.node.SetManagement(ctx, &cryptosv1.SetManagementRequest{Management: m})
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
