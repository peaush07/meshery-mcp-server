package security

import (
	"encoding/json"
	"fmt"
	"strings"
)

const RedactedPlaceholder = "[REDACTED_SECRET]"

// Sensitive key patterns to match accurately.
var exactSensitiveKeys = map[string]bool{
	"token":          true,
	"password":       true,
	"secret":         true,
	"private_key":    true,
	"kubeconfig":     true,
	"auth_token":     true,
	"authtoken":      true,
	"api_key":        true,
	"apikey":         true,
	"access_token":   true,
	"accesstoken":    true,
	"pass":           true,
	"session":        true,
	"session_cookie": true,
	"authorization":  true,
}

// Exceptions that should NOT be redacted despite matching substrings
var allowedExceptions = map[string]bool{
	"author":       true,
	"authority":    true,
	"authorized":   true,
	"token_type":   true,
	"passthrough":  true,
	"pass_through": true,
}

// SanitizeMap deeply copies and redacts sensitive information from map hierarchies.
func SanitizeMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}

	result := make(map[string]interface{}, len(input))

	for k, v := range input {
		if isSensitiveKey(k) {
			result[k] = RedactedPlaceholder
			continue
		}

		switch val := v.(type) {
		case map[string]interface{}:
			result[k] = SanitizeMap(val)
		case []interface{}:
			result[k] = sanitizeSlice(val)
		case string:
			result[k] = SanitizeString(val)
		default:
			result[k] = v
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
		keyVariations := []string{key, fmt.Sprintf("\"%s\"", key)}
		for _, k := range keyVariations {
			for _, sep := range []string{"=", ": ", ":"} {
				pattern := k + sep
				for {
					lowerResult := strings.ToLower(result)
					idx := strings.Index(lowerResult, strings.ToLower(pattern))
					if idx == -1 {
						break
					}
					valStart := idx + len(pattern)

					// Check for "Bearer token" pattern or JSON quote boundary
					remainder := result[valStart:]
					if strings.HasPrefix(strings.ToLower(remainder), "bearer ") {
						valStart += len("bearer ")
					} else if len(remainder) > 0 && remainder[0] == '"' {
						valStart++
					}

					valEnd := strings.IndexAny(result[valStart:], " \t\n\r\"',;}")
					if valEnd == -1 {
						result = result[:idx+len(pattern)] + RedactedPlaceholder
						break
					} else {
						endIdx := valStart + valEnd
						if endIdx < len(result) && result[endIdx] == '"' {
							endIdx++
						}
						result = result[:idx+len(pattern)] + RedactedPlaceholder + result[endIdx:]
					}
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
		case string:
			result[i] = SanitizeString(child)
		default:
			result[i] = item
		}
	}

	return result
}

func sanitizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return SanitizeMap(val)
	case []interface{}:
		return sanitizeSlice(val)
	case string:
		return SanitizeString(val)
	default:
		return v
	}
}
