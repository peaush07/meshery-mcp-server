package tools

import (
	"context"
	"fmt"

	"github.com/meshery-extensions/meshery-mcp-server/pkg/meshery"
	"github.com/meshery-extensions/meshery-mcp-server/pkg/security"
)

// ListDesignsTool implements the MCP tool contract for listing Meshery design patterns (Issue #30).
type ListDesignsTool struct {
	client meshery.Client
}

// NewListDesignsTool constructs a new ListDesignsTool instance.
func NewListDesignsTool(client meshery.Client) *ListDesignsTool {
	return &ListDesignsTool{client: client}
}

func (t *ListDesignsTool) Name() string {
	return "list_designs"
}

func (t *ListDesignsTool) Description() string {
	return "Lists all available Meshery cloud-native design patterns and infrastructure specifications."
}

func (t *ListDesignsTool) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
}

// Execute queries Meshery API and returns response-boundary sanitized design objects.
func (t *ListDesignsTool) Execute(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	designs, err := t.client.ListDesigns(ctx)
	if err != nil {
		sanitizedErr := security.SanitizeString(err.Error())
		return nil, fmt.Errorf("list_designs failure: %s", sanitizedErr)
	}

	sanitizedDesigns := make([]interface{}, len(designs))
	for i, d := range designs {
		sanitizedDesigns[i] = security.SanitizeMap(d)
	}

	return map[string]interface{}{
		"total_count": len(sanitizedDesigns),
		"designs":     sanitizedDesigns,
	}, nil
}
