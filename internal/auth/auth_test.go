package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-api-key")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expectedAPIKey := "my-api-key"
	if apiKey != expectedAPIKey {
		t.Errorf("expected API key %q, got %q", expectedAPIKey, apiKey)
	}

	// Test case for missing Authorization header
	headers.Del("Authorization")
	_, err = GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}

	// Test case for malformed Authorization header
	headers.Set("Authorization", "Bearer token")
	_, err = GetAPIKey(headers)
	expectedErr := errors.New("malformed authorization header")
	if err.Error() != expectedErr.Error() {
		t.Errorf("expected error %q, got %q", expectedErr, err)
	}
}
