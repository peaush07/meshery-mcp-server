// Package security provides response boundary secret sanitization and redaction engines
// to prevent credentials, bearer tokens, API keys, and session secrets from leaking through MCP tool outputs.
package security

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// RedactedPlaceholder is the standardized replacement string for sensitive values.
const RedactedPlaceholder = "[REDACTED_SECRET]"

// CircularPlaceholder is the replacement string used when a circular/cyclic data structure is detected.
const CircularPlaceholder = "[CIRCULAR_REFERENCE]"

const maxRecursionDepth = 64

// Exact sensitive key names that trigger redaction.
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

// Exceptions that must NOT be redacted despite containing common substrings.
var allowedExceptions = map[string]bool{
	"secretary":     true,
	"author":        true,
	"authority":     true,
	"authorized":    true,
	"token_type":    true,
	"token_count":   true,
	"tokencount":    true,
	"passthrough":   true,
	"pass_through":  true,
	"password_hint": true,
}

// SanitizeMap deeply copies and redacts sensitive information from map hierarchies.
// It tracks visited pointer references to prevent infinite recursion on cyclic data structures.
func SanitizeMap(input map[string]interface{}) map[string]interface{} {
	visited := make(map[uintptr]bool)
	return sanitizeMapInternal(input, visited, 0)
}

func sanitizeMapInternal(input map[string]interface{}, visited map[uintptr]bool, depth int) map[string]interface{} {
	if input == nil {
		return nil
	}
	if depth > maxRecursionDepth {
		return map[string]interface{}{"error": CircularPlaceholder}
	}

	valPtr := reflect.ValueOf(input).Pointer()
	if valPtr != 0 {
		if visited[valPtr] {
			return map[string]interface{}{"cycle": CircularPlaceholder}
		}
		visited[valPtr] = true
		defer delete(visited, valPtr)
	}

	result := make(map[string]interface{}, len(input))

	for k, v := range input {
		if isSensitiveKey(k) {
			result[k] = RedactedPlaceholder
			continue
		}

		switch val := v.(type) {
		case map[string]interface{}:
			result[k] = sanitizeMapInternal(val, visited, depth+1)
		case []interface{}:
			result[k] = sanitizeSliceInternal(val, visited, depth+1)
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

	visited := make(map[uintptr]bool)
	sanitizedData := sanitizeValueInternal(data, visited, 0)
	return json.Marshal(sanitizedData)
}

// SanitizeString scrubs sensitive token or credential patterns from error messages and log outputs.
// It formats Authorization Bearer values cleanly as "Bearer [REDACTED_SECRET]" without leaking token contents.
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
				searchIdx := 0
				for {
					if searchIdx >= len(result) {
						break
					}
					lowerResult := strings.ToLower(result[searchIdx:])
					idx := strings.Index(lowerResult, strings.ToLower(pattern))
					if idx == -1 {
						break
					}
					realIdx := searchIdx + idx
					valStart := realIdx + len(pattern)
					remainder := result[valStart:]

					hasQuote := false
					if len(remainder) > 0 && remainder[0] == '"' {
						hasQuote = true
						valStart++
						remainder = result[valStart:]
					}

					prefix := ""
					if strings.HasPrefix(strings.ToLower(remainder), "bearer ") {
						prefix = "Bearer "
						valStart += len("bearer ")
					}

					valEnd := strings.IndexAny(result[valStart:], " \t\n\r\"',;}")
					var endIdx int
					if valEnd == -1 {
						endIdx = len(result)
					} else {
						endIdx = valStart + valEnd
						if hasQuote && endIdx < len(result) && result[endIdx] == '"' {
							endIdx++
						}
					}

					replacement := prefix + RedactedPlaceholder
					result = result[:realIdx+len(pattern)] + replacement + result[endIdx:]
					searchIdx = realIdx + len(pattern) + len(replacement)
				}
			}
		}
	}
	return result
}

// Helper: delimiter-bounded key matching to prevent over-redaction (e.g., secretary -> NOT redacted).
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	if allowedExceptions[lower] {
		return false
	}
	if exactSensitiveKeys[lower] {
		return true
	}

	tokens := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == '@' || r == '/' || r == ' '
	})

	for _, token := range tokens {
		if exactSensitiveKeys[token] && !allowedExceptions[lower] {
			return true
		}
	}
	return false
}

func sanitizeSliceInternal(s []interface{}, visited map[uintptr]bool, depth int) []interface{} {
	if s == nil {
		return nil
	}
	if depth > maxRecursionDepth {
		return []interface{}{CircularPlaceholder}
	}

	valPtr := reflect.ValueOf(s).Pointer()
	if valPtr != 0 {
		if visited[valPtr] {
			return []interface{}{CircularPlaceholder}
		}
		visited[valPtr] = true
		defer delete(visited, valPtr)
	}

	result := make([]interface{}, len(s))
	for i, item := range s {
		switch child := item.(type) {
		case map[string]interface{}:
			result[i] = sanitizeMapInternal(child, visited, depth+1)
		case []interface{}:
			result[i] = sanitizeSliceInternal(child, visited, depth+1)
		case string:
			result[i] = SanitizeString(child)
		default:
			result[i] = item
		}
	}

	return result
}

func sanitizeValueInternal(v interface{}, visited map[uintptr]bool, depth int) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return sanitizeMapInternal(val, visited, depth+1)
	case []interface{}:
		return sanitizeSliceInternal(val, visited, depth+1)
	case string:
		return SanitizeString(val)
	default:
		return v
	}
}
