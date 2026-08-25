package meshery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/meshery-extensions/meshery-mcp-server/pkg/security"
)

// Client defines the interface for communicating with Meshery Server APIs.
type Client interface {
	ListDesigns(ctx context.Context) ([]map[string]interface{}, error)
}

type mesheryClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient returns a new Meshery API client instance with optional Bearer token authentication.
func NewClient(baseURL string, token ...string) Client {
	if baseURL == "" {
		baseURL = "http://localhost:9081"
	}
	t := ""
	if len(token) > 0 {
		t = token[0]
	}
	return &mesheryClient{
		baseURL: baseURL,
		token:   t,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ListDesigns retrieves available design patterns from Meshery Server /api/pattern endpoint.
func (c *mesheryClient) ListDesigns(ctx context.Context) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/pattern", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create list_designs request: %w", err)
	}

	if c.token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		sanitizedErr := security.SanitizeString(err.Error())
		return nil, fmt.Errorf("failed to execute list_designs HTTP query: %s", sanitizedErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		sanitizedBody := security.SanitizeString(string(body))
		return nil, fmt.Errorf("meshery API returned status %d: %s", resp.StatusCode, sanitizedBody)
	}

	var payload struct {
		Patterns []map[string]interface{} `json:"patterns"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("failed to decode list_designs JSON response: %w", err)
	}

	return payload.Patterns, nil
}
