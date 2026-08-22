package security

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

const RedactedPlaceholder = "[REDACTED_SECRET]"

// exactSensitiveKeys holds key tokens to scrub (case-insensitive)
var exactSensitiveKeys = map[string]bool{
	"token":          true,
	"password":       true,
	"secret":         true,
	"kubeconfig":     true,
	"api_key":        true,
	"apikey":         true,
	"private_key":    true,
	"session":        true,
	"session_cookie": true,
	"authorization":  true,
}

// allowedExceptions prevents false-positive over-redaction of non-sensitive keys (e.g., author)
var allowedExceptions = map[string]bool{
	"author":     true,
	"authority":  true,
	"authorized": true,
	"token_type": true,
}

// SanitizeMap takes a generic map or payload structure and returns a sanitized deep-copy.
func SanitizeMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}
	result := make(map[string]interface{}, len(input))
	for k, v := range input {
		if isSensitiveKey(k) {
			result[k] = RedactedPlaceholder
		} else {
			result[k] = sanitizeValue(v)
		}
	}
	return result
}

// SanitizeJSON parses raw JSON, scrubs sensitive keys, and returns sanitized JSON bytes.
func SanitizeJSON(rawJSON []byte) ([]byte, error) {
	if len(rawJSON) == 0 {
		return rawJSON, nil
	}

	var data interface{}
	if err := json.Unmarshal(rawJSON, &data); err != nil {
		// Fallback to string-based error path redaction for non-JSON or malformed payloads
		sanitizedStr := SanitizeString(string(rawJSON))
		return []byte(sanitizedStr), nil
	}

	sanitizedData := sanitizeValue(data)
	return json.Marshal(sanitizedData)
}

// SanitizeString scrubs sensitive token or credential patterns from error messages and logs.
func SanitizeString(input string) string {
	if input == "" {
		return input
	}
	result := input
	for key := range exactSensitiveKeys {
		for _, sep := range []string{"=", ": ", ":"} {
			pattern := key + sep
			if idx := strings.Index(strings.ToLower(result), pattern); idx != -1 {
				valStart := idx + len(pattern)
				valEnd := strings.IndexAny(result[valStart:], " \t\n\r\"',;")
				if valEnd == -1 {
					result = result[:valStart] + RedactedPlaceholder
				} else {
					result = result[:valStart] + RedactedPlaceholder + result[valStart+valEnd:]
				}
			}
		}
	}
	return result
}

// Helper: check if key matches sensitive key list or sensitive substrings
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	if allowedExceptions[lower] {
		return false
	}
	if exactSensitiveKeys[lower] {
		return true
	}
	for sensitiveKey := range exactSensitiveKeys {
		if strings.Contains(lower, sensitiveKey) && !allowedExceptions[lower] {
			return true
		}
	}
	return false
}

// Helper: recursively sanitize map, slice, array, or typed values
func sanitizeValue(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	val := reflect.ValueOf(v)
	switch val.Kind() {
	case reflect.Map:
		outMap := make(map[string]interface{})
		for _, k := range val.MapKeys() {
			keyStr := fmt.Sprintf("%v", k.Interface())
			elemVal := val.MapIndex(k).Interface()
			if isSensitiveKey(keyStr) {
				outMap[keyStr] = RedactedPlaceholder
			} else {
				outMap[keyStr] = sanitizeValue(elemVal)
			}
		}
		return outMap

	case reflect.Slice, reflect.Array:
		outSlice := make([]interface{}, val.Len())
		for i := 0; i < val.Len(); i++ {
			outSlice[i] = sanitizeValue(val.Index(i).Interface())
		}
		return outSlice

	default:
		return v
	}
}
