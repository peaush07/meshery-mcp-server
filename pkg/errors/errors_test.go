package errors

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMeshKitErrors_Contract(t *testing.T) {
	errAuth := ErrUnauthenticated(nil)
	if errAuth == nil {
		t.Fatalf("expected ErrUnauthenticated error, got nil")
	}

	errUpstream := ErrUpstreamFailed(nil)
	if errUpstream == nil {
		t.Fatalf("expected ErrUpstreamFailed error, got nil")
	}

	errSchema := ErrSchemaInvalid(nil)
	if errSchema == nil {
		t.Fatalf("expected ErrSchemaInvalid error, got nil")
	}
}

func TestMeshKitErrors_JSONWireFormat(t *testing.T) {
	errAuth := ErrUnauthenticated(nil)
	rawJSON, err := json.Marshal(errAuth)
	if err != nil {
		t.Fatalf("failed to marshal MeshKit error to JSON: %v", err)
	}

	jsonStr := string(rawJSON)
	if !strings.Contains(jsonStr, ErrUnauthenticatedCode) {
		t.Errorf("expected JSON wire format to contain error code %s, got: %s", ErrUnauthenticatedCode, jsonStr)
	}

	if !strings.Contains(jsonStr, "Authentication Failure") {
		t.Errorf("expected JSON wire format to contain short description, got: %s", jsonStr)
	}
}
