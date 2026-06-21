// Package client is the HTTP client for the Palisade control plane API.
//
// Over plaintext http (the local demo) the agent authenticates with a bearer
// token (the agent_secret). Over https the agent presents the client
// certificate issued at enrollment for mutual TLS: the cert+key are loaded into
// http.Transport.TLSClientConfig and, when a CA PEM is supplied, trusted as the
// RootCAs pool. The bearer header is still sent; the server prefers the cert.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"palisade/agent/internal/catalog"
)

// Client talks to the control plane at BaseURL.
type Client struct {
	BaseURL string
	Secret  string // agent_secret; empty during enroll
	hc      *http.Client
}

// New returns a Client. server is the base URL (scheme+host), secret may be
// empty for the enroll call. It uses the default transport (no client cert),
// suitable for the plaintext demo and the enroll call (no cert issued yet).
func New(server, secret string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(server, "/"),
		Secret:  secret,
		hc:      &http.Client{Timeout: 30 * time.Second},
	}
}

// NewWithCerts returns a Client that presents the enrollment client
// certificate for mutual TLS when server is an https URL and certPEM+keyPEM are
// non-empty. caPEM, when present, becomes the RootCAs pool. Over http, or when
// no cert material is supplied, it behaves exactly like New. It returns an error
// if the supplied PEM material fails to parse.
func NewWithCerts(server, secret, certPEM, keyPEM, caPEM string) (*Client, error) {
	c := New(server, secret)
	if !strings.HasPrefix(c.BaseURL, "https://") || certPEM == "" || keyPEM == "" {
		return c, nil
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("parse CA certificate: no PEM blocks found")
		}
		tlsCfg.RootCAs = pool
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	c.hc.Transport = tr
	return c, nil
}

func (c *Client) do(ctx context.Context, method, path string, reqBody, respBody any) error {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.Secret)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}

	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// Enroll calls POST /v1/agents/enroll.
func (c *Client) Enroll(ctx context.Context, req catalog.EnrollRequest) (*catalog.EnrollResponse, error) {
	var out catalog.EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/v1/agents/enroll", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat calls POST /v1/agents/{id}/heartbeat.
func (c *Client) Heartbeat(ctx context.Context, agentID string, req catalog.HeartbeatRequest) (*catalog.HeartbeatResponse, error) {
	var out catalog.HeartbeatResponse
	path := fmt.Sprintf("/v1/agents/%s/heartbeat", agentID)
	if err := c.do(ctx, http.MethodPost, path, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SubmitAssets calls POST /v1/agents/{id}/assets.
func (c *Client) SubmitAssets(ctx context.Context, agentID string, req catalog.AssetsRequest) (*catalog.AssetsResponse, error) {
	var out catalog.AssetsResponse
	path := fmt.Sprintf("/v1/agents/%s/assets", agentID)
	if err := c.do(ctx, http.MethodPost, path, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Bundle calls GET /v1/catalog/bundle?since=<since>.
func (c *Client) Bundle(ctx context.Context, since int) (*catalog.Bundle, error) {
	var out catalog.Bundle
	path := fmt.Sprintf("/v1/catalog/bundle?since=%d", since)
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SubmitFindings calls POST /v1/scans/{scan_id}/findings.
func (c *Client) SubmitFindings(ctx context.Context, scanID string, req catalog.FindingsRequest) error {
	path := fmt.Sprintf("/v1/scans/%s/findings", scanID)
	return c.do(ctx, http.MethodPost, path, req, nil)
}
