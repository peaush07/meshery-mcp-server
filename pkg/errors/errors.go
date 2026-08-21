package errors

import (
	"fmt"
)

// MeshKitError represents a structured error compliant with Meshery MeshKit conventions.
type MeshKitError struct {
	Code             string `json:"code"`
	ShortDescription string `json:"short_description"`
	LongDescription  string `json:"long_description"`
	ProbableCause    string `json:"probable_cause"`
	Remediation      string `json:"remediation"`
}

func (e *MeshKitError) Error() string {
	return fmt.Sprintf("[%s] %s: %s (Remediation: %s)", e.Code, e.ShortDescription, e.LongDescription, e.Remediation)
}

// Common Meshery MCP Server Error Code Definitions
var (
	ErrUnauthenticated = &MeshKitError{
		Code:             "1001-MCP",
		ShortDescription: "Authentication Failure",
		LongDescription:  "Failed to authenticate inbound request against Meshery REST/GraphQL provider.",
		ProbableCause:    "Invalid or expired token cookie, missing session credentials.",
		Remediation:      "Provide a valid Meshery session cookie or authenticate via mesheryctl login.",
	}

	ErrConnectionFailed = &MeshKitError{
		Code:             "1002-MCP",
		ShortDescription: "Upstream Meshery Server Unreachable",
		LongDescription:  "Unable to establish network connection to target Meshery Server API endpoint.",
		ProbableCause:    "Meshery Server container/binary is not running on target URL.",
		Remediation:      "Ensure Meshery Server is running (systemctl / docker) and verify -meshery-url flag.",
	}

	ErrInvalidToolParams = &MeshKitError{
		Code:             "1003-MCP",
		ShortDescription: "Invalid MCP Tool Parameters",
		LongDescription:  "JSON-RPC tools/call parameters failed schema validation.",
		ProbableCause:    "Missing required fields or invalid argument types in tool call payload.",
		Remediation:      "Check tool schema definition via tools/list and provide valid parameters.",
	}
)
