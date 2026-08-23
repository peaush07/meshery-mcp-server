package tools

import (
	"context"
	"fmt"
	"testing"
)

type mockMesheryClient struct {
	designs []map[string]interface{}
	err     error
}

func (m *mockMesheryClient) ListDesigns(ctx context.Context) ([]map[string]interface{}, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.designs, nil
}

func TestListDesignsTool_Execute_Success(t *testing.T) {
	mockClient := &mockMesheryClient{
		designs: []map[string]interface{}{
			{
				"id":     "design-001",
				"name":   "K8s-Deployment-Pattern",
				"secret": "bearer-token-secret-123", // Should be sanitized!
			},
		},
	}

	tool := NewListDesignsTool(mockClient)
	result, err := tool.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error executing list_designs tool: %v", err)
	}

	if result["total_count"] != 1 {
		t.Errorf("expected total_count 1, got %v", result["total_count"])
	}

	designs := result["designs"].([]interface{})
	d0 := designs[0].(map[string]interface{})

	if d0["id"] != "design-001" {
		t.Errorf("expected id design-001, got %v", d0["id"])
	}

	if d0["secret"] != "[REDACTED_SECRET]" {
		t.Errorf("expected secret to be redacted by response boundary sanitizer, got %v", d0["secret"])
	}
}

func TestListDesignsTool_Execute_ErrorPath(t *testing.T) {
	mockClient := &mockMesheryClient{
		err: fmt.Errorf("connection refused: token=raw-secret-123"),
	}

	tool := NewListDesignsTool(mockClient)
	_, err := tool.Execute(context.Background(), nil)
	if err == nil {
		t.Fatalf("expected error from list_designs execution, got nil")
	}

	// Verify error path sanitization
	if err.Error() == "list_designs failure: connection refused: token=raw-secret-123" {
		t.Errorf("error path unredacted token leak detected: %v", err)
	}
}
