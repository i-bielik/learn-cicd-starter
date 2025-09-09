package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	cases := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			expectedKey:   "my-secret-api-key",
			expectedError: nil,
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header - Wrong Scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-api-key"},
			},
			expectedKey:   "",
			expectedError: newError("malformed authorization header"),
		},
		{
			name: "Malformed Header - Missing Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: newError("malformed authorization header"),
		},
		{
			name: "Malformed Header - Empty Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey:   "",
			expectedError: newError("malformed authorization header"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if key != tc.expectedKey {
				t.Errorf("expected key '%s', got '%s'", tc.expectedKey, key)
			}

			if tc.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				if err.Error() != tc.expectedError.Error() {
					t.Errorf("expected error '%v', got '%v'", tc.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("did not expect error but got one: %v", err)
				}
			}
		})
	}
}

// Helper to create a new error for comparison, as direct comparison of errors.New() fails.
func newError(msg string) error {
	return &customError{msg}
}

type customError struct{ msg string }

func (e *customError) Error() string { return e.msg }
