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
	return "Lists available Meshery cloud-native design patterns and infrastructure specifications with optional pagination and search filters."
}

func (t *ListDesignsTool) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"page": map[string]interface{}{
				"type":        "integer",
				"description": "Page number for paginated results (default: 1).",
			},
			"pageSize": map[string]interface{}{
				"type":        "integer",
				"description": "Number of design patterns per page (default: 10).",
			},
			"search": map[string]interface{}{
				"type":        "string",
				"description": "Optional search term to filter design patterns by name or description.",
			},
		},
	}
}

// Execute queries Meshery API and returns response-boundary sanitized design objects.
func (t *ListDesignsTool) Execute(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	page := 1
	pageSize := 10
	search := ""

	if params != nil {
		if p, ok := params["page"].(float64); ok {
			page = int(p)
		} else if pInt, ok := params["page"].(int); ok {
			page = pInt
		}

		if ps, ok := params["pageSize"].(float64); ok {
			pageSize = int(ps)
		} else if psInt, ok := params["pageSize"].(int); ok {
			pageSize = psInt
		}

		if s, ok := params["search"].(string); ok {
			search = s
		}
	}

	designs, totalCount, err := t.client.ListDesigns(ctx, page, pageSize, search)
	if err != nil {
		sanitizedErr := security.SanitizeString(err.Error())
		return nil, fmt.Errorf("list_designs failure: %s", sanitizedErr)
	}

	sanitizedDesigns := make([]interface{}, len(designs))
	for i, d := range designs {
		sanitizedDesigns[i] = security.SanitizeMap(d)
	}

	return map[string]interface{}{
		"page":        page,
		"pageSize":    pageSize,
		"total_count": totalCount,
		"designs":     sanitizedDesigns,
	}, nil
}
