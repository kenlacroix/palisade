// Package client is the HTTP client for the Palisade control plane API.
//
// Auth for this scaffold is a bearer token (the agent_secret). Production
// target is mTLS.
//
// TODO(mTLS): replace bearer auth with mutual TLS using the client cert
// issued at enrollment. The enroll flow already maps cleanly: swap the
// returned agent_secret for a client certificate and configure
// http.Transport.TLSClientConfig with it.
package client

import (
	"bytes"
	"context"
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
// empty for the enroll call.
func New(server, secret string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(server, "/"),
		Secret:  secret,
		hc:      &http.Client{Timeout: 30 * time.Second},
	}
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
