package security

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Sensitive key patterns to match accurately.
var exactSensitiveKeys = map[string]bool{
	"token": true, "password": true, "secret": true, "private_key": true,
	"kubeconfig": true, "auth_token": true, "authtoken": true, "api_key": true,
	"apikey": true, "access_token": true, "accesstoken": true, "pass": true,
}

// SanitizeJSON inspects JSON structures and redacts sensitive field values.
func SanitizeJSON(rawJSON []byte) ([]byte, error) {
	if len(rawJSON) == 0 {
		return rawJSON, nil
	}

	var genericMap map[string]interface{}
	if err := json.Unmarshal(rawJSON, &genericMap); err != nil {
		// If malformed or non-object JSON, sanitize as raw string error path
		return []byte(SanitizeString(string(rawJSON))), nil
	}

	sanitized := SanitizeMap(genericMap)
	return json.Marshal(sanitized)
}

// SanitizeMap recursively redacts sensitive key/value pairs, producing a sanitized map.
func SanitizeMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	// Create a deep copy to guarantee non-mutation of original caller map
	result := make(map[string]interface{})
	for k, v := range m {
		keyLower := strings.ToLower(k)
		if isSensitiveKey(keyLower) {
			result[k] = "[REDACTED_SECRET]"
			continue
		}

		switch val := v.(type) {
		case map[string]interface{}:
			result[k] = SanitizeMap(val)
		case []interface{}:
			result[k] = sanitizeSlice(val)
		default:
			result[k] = v
		}
	}
	return result
}

// SanitizeString scrubs sensitive tokens or credentials from arbitrary strings or error paths.
func SanitizeString(s string) string {
	lower := strings.ToLower(s)
	for key := range exactSensitiveKeys {
		if strings.Contains(lower, key) && strings.Contains(s, "=") {
			// Redact potential key=val occurrences in error strings
			parts := strings.Split(s, "=")
			if len(parts) == 2 {
				return fmt.Sprintf("%s=[REDACTED_SECRET]", parts[0])
			}
		}
	}
	return s
}

func isSensitiveKey(key string) bool {
	if exactSensitiveKeys[key] {
		return true
	}
	for sensitive := range exactSensitiveKeys {
		if strings.HasSuffix(key, sensitive) || strings.HasPrefix(key, sensitive) {
			// Avoid over-redaction (e.g., 'author' or 'authority' should NOT be redacted)
			if key == "author" || key == "authority" || key == "authorize" {
				return false
			}
			return true
		}
	}
	return false
}

func sanitizeSlice(s []interface{}) []interface{} {
	if s == nil {
		return nil
	}
	result := make([]interface{}, len(s))
	for i, item := range s {
		switch child := item.(type) {
		case map[string]interface{}:
			result[i] = SanitizeMap(child)
		case []interface{}:
			result[i] = sanitizeSlice(child)
		default:
			result[i] = item
		}
	}
	return result
}
