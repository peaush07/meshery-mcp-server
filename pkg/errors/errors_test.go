package errors

import (
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
