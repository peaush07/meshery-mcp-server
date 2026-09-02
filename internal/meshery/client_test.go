package meshery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMesheryClient_ListDesigns_QueryStringAndDualCookies(t *testing.T) {
	var capturedPage, capturedPageSize, capturedSearch, capturedAuth string
	var capturedTokenCookie, capturedProviderCookie *http.Cookie

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPage = r.URL.Query().Get("page")
		capturedPageSize = r.URL.Query().Get("pagesize")
		capturedSearch = r.URL.Query().Get("search")
		capturedAuth = r.Header.Get("Authorization")

		capturedTokenCookie, _ = r.Cookie("token")
		capturedProviderCookie, _ = r.Cookie("meshery-provider")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Meshery Server sends totalCount (PascalCase camelTag matching PatternsAPIResponse)
		_, _ = w.Write([]byte(`{"totalCount": 15, "patterns": [{"id": "p-1", "name": "K8s-Pattern"}]}`))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "test-bearer-token", "Meshery")

	designs, totalCount, err := client.ListDesigns(context.Background(), 2, 25, "kubernetes")
	if err != nil {
		t.Fatalf("unexpected error querying ListDesigns: %v", err)
	}

	if totalCount != 15 {
		t.Errorf("expected totalCount 15 from totalCount tag, got %d", totalCount)
	}

	if len(designs) != 1 {
		t.Errorf("expected 1 design, got %d", len(designs))
	}

	if capturedPage != "2" {
		t.Errorf("expected query page=2, got %s", capturedPage)
	}

	if capturedPageSize != "25" {
		t.Errorf("expected query pagesize=25, got %s", capturedPageSize)
	}

	if capturedSearch != "kubernetes" {
		t.Errorf("expected query search=kubernetes, got %s", capturedSearch)
	}

	if capturedAuth != "Bearer test-bearer-token" {
		t.Errorf("expected Authorization header Bearer test-bearer-token, got %s", capturedAuth)
	}

	if capturedTokenCookie == nil || capturedTokenCookie.Value != "test-bearer-token" {
		t.Errorf("expected token cookie test-bearer-token, got %v", capturedTokenCookie)
	}

	if capturedProviderCookie == nil || capturedProviderCookie.Value != "Meshery" {
		t.Errorf("expected meshery-provider cookie Meshery, got %v", capturedProviderCookie)
	}
}
