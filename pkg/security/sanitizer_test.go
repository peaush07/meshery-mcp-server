package security

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeMap_SensitiveKeys(t *testing.T) {
	input := map[string]interface{}{
		"username": "admin",
		"password": "supersecretpassword123",
		"token":    "bearer-token-xyz-789",
		"cluster":  "k8s-prod-cluster",
	}

	sanitized := SanitizeMap(input)

	if sanitized["password"] != RedactedPlaceholder {
		t.Errorf("expected password to be redacted, got %v", sanitized["password"])
	}
	if sanitized["token"] != RedactedPlaceholder {
		t.Errorf("expected token to be redacted, got %v", sanitized["token"])
	}
	if sanitized["username"] != "admin" {
		t.Errorf("expected username to be admin, got %v", sanitized["username"])
	}
}

func TestSanitizeMap_SecretaryNotRedacted(t *testing.T) {
	input := map[string]interface{}{
		"secretary":     "john_doe",
		"token_count":   100,
		"password_hint": "first pet name",
	}

	sanitized := SanitizeMap(input)

	if sanitized["secretary"] != "john_doe" {
		t.Errorf("expected secretary to remain unredacted, got %v", sanitized["secretary"])
	}
	if sanitized["token_count"] != 100 {
		t.Errorf("expected token_count to remain unredacted, got %v", sanitized["token_count"])
	}
}

func TestSanitizeMap_CyclicMap(t *testing.T) {
	input := map[string]interface{}{
		"name": "cyclic-test",
	}
	input["self"] = input

	sanitized := SanitizeMap(input)
	if sanitized == nil {
		t.Fatalf("expected non-nil sanitized map for cyclic input")
	}

	selfVal := sanitized["self"].(map[string]interface{})
	if selfVal["cycle"] != CircularPlaceholder {
		t.Errorf("expected cyclic reference placeholder %s, got %v", CircularPlaceholder, selfVal["cycle"])
	}
}

func TestSanitizeString_AuthorizationBearerRedaction(t *testing.T) {
	rawInput := "Authorization: Bearer my-secret-auth-token-12345"
	sanitized := SanitizeString(rawInput)

	if strings.Contains(sanitized, "my-secret-auth-token-12345") {
		t.Errorf("raw secret token leaked in sanitized string: %s", sanitized)
	}

	if !strings.Contains(sanitized, "Bearer "+RedactedPlaceholder) {
		t.Errorf("expected Bearer prefix to be preserved with placeholder, got: %s", sanitized)
	}
}

func TestSanitizeString_QuotedJSONAuthorization(t *testing.T) {
	rawInput := `{"Authorization": "Bearer secret-token-abc987", "status": "active"}`
	sanitized := SanitizeString(rawInput)

	if strings.Contains(sanitized, "secret-token-abc987") {
		t.Errorf("raw secret token leaked in quoted JSON string: %s", sanitized)
	}

	if !strings.Contains(sanitized, "Bearer "+RedactedPlaceholder) {
		t.Errorf("expected Bearer placeholder in JSON string, got: %s", sanitized)
	}
}

func TestSanitizeMap_NestedStructures(t *testing.T) {
	input := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name": "meshery-design",
			"credentials": map[string]interface{}{
				"kubeconfig": "apiVersion: v1...",
				"api_key":    "key-12345",
			},
		},
		"endpoints": []interface{}{
			map[string]interface{}{
				"url":   "https://mesh.local",
				"token": "secret-auth-token",
			},
		},
	}

	sanitized := SanitizeMap(input)

	metadata := sanitized["metadata"].(map[string]interface{})
	creds := metadata["credentials"].(map[string]interface{})

	if creds["kubeconfig"] != RedactedPlaceholder {
		t.Errorf("expected kubeconfig to be redacted, got %v", creds["kubeconfig"])
	}
	if creds["api_key"] != RedactedPlaceholder {
		t.Errorf("expected api_key to be redacted, got %v", creds["api_key"])
	}

	endpoints := sanitized["endpoints"].([]interface{})
	ep0 := endpoints[0].(map[string]interface{})
	if ep0["token"] != RedactedPlaceholder {
		t.Errorf("expected endpoint token to be redacted, got %v", ep0["token"])
	}
}

func TestSanitizeJSON_ValidJSON(t *testing.T) {
	rawJSON := []byte(`{"service":"meshery","secret_key":"topsecret123","status":"active"}`)

	sanitizedBytes, err := SanitizeJSON(rawJSON)
	if err != nil {
		t.Fatalf("unexpected error sanitizing JSON: %v", err)
	}

	var resultMap map[string]interface{}
	if err := json.Unmarshal(sanitizedBytes, &resultMap); err != nil {
		t.Fatalf("failed to unmarshal sanitized JSON: %v", err)
	}

	if resultMap["secret_key"] != RedactedPlaceholder {
		t.Errorf("expected secret_key to be redacted, got %v", resultMap["secret_key"])
	}
}
