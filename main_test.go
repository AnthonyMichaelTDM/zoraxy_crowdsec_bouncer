package main

import (
	"net/http"
	"testing"

	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
)

func TestGetRealIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{
			name:       "Basic IP without headers",
			remoteAddr: "192.168.1.100",
			headers:    map[string]string{},
			expected:   "192.168.1.100",
		},
		{
			name:       "IP with port, no headers",
			remoteAddr: "192.168.1.100:8080",
			headers:    map[string]string{},
			expected:   "192.168.1.100",
		},
		{
			name:       "IPv6 with port",
			remoteAddr: "[2001:db8::1]:8080",
			headers:    map[string]string{},
			expected:   "2001:db8::1",
		},
		{
			name:       "X-Real-IP header takes precedence",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string]string{
				"X-Real-IP": "10.0.0.5",
			},
			expected: "10.0.0.5",
		},
		{
			name:       "X-Real-IP with port",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string]string{
				"X-Real-IP": "10.0.0.5:9090",
			},
			expected: "10.0.0.5",
		},
		{
			name:       "CF-Connecting-IP when X-Real-IP is empty",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string]string{
				"X-Real-IP":        "",
				"CF-Connecting-IP": "203.0.113.10",
			},
			expected: "203.0.113.10",
		},
		{
			name:       "CF-Connecting-IP with port",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.10:443",
			},
			expected: "203.0.113.10",
		},
		{
			name:       "X-Real-IP takes precedence over CF-Connecting-IP",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string]string{
				"X-Real-IP":        "10.0.0.5",
				"CF-Connecting-IP": "203.0.113.10",
			},
			expected: "10.0.0.5",
		},
		{
			name:       "Multiple colons in IPv6 address",
			remoteAddr: "2001:db8:85a3:8d3:1319:8a2e:370:7348",
			headers:    map[string]string{},
			expected:   "2001:db8:85a3:8d3:1319:8a2e:370:7348",
		},
		{
			name:       "Header with IPv6",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string]string{
				"X-Real-IP": "2001:db8::1",
			},
			expected: "2001:db8::1",
		},
		{
			name:       "Header with IPv6 and port",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string]string{
				"X-Real-IP": "[2001:db8::1]:443",
			},
			expected: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock request
			req, err := http.NewRequest("GET", "/test", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.RemoteAddr = tt.remoteAddr

			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Create a mock DynamicSniffForwardRequest
			dsfr := &plugin.DynamicSniffForwardRequest{
				RemoteAddr: tt.remoteAddr,
			}
			dsfr.SetRequest(req)

			// Call the function
			result, err := GetRealIP(dsfr)
			if err != nil {
				t.Errorf("GetRealIP() error = %v", err)
			}

			// Check the result
			if result != tt.expected {
				t.Errorf("GetRealIP() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// Benchmark the GetRealIP function
func BenchmarkGetRealIP(b *testing.B) {
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "10.0.0.5")

	dsfr := &plugin.DynamicSniffForwardRequest{
		RemoteAddr: "192.168.1.100:8080",
	}
	dsfr.SetRequest(req)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetRealIP(dsfr)
	}
}

// Test edge cases and error conditions
func TestGetRealIPEdgeCases(t *testing.T) {
	t.Run("Nil request should not panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GetRealIP panicked with nil request: %v", r)
			}
		}()

		dsfr := &plugin.DynamicSniffForwardRequest{
			RemoteAddr: "192.168.1.100:8080",
		}
		// Don't set a request (it will be nil)

		result, err := GetRealIP(dsfr)
		if err != nil {
			t.Errorf("GetRealIP returned an error: %v", err)
		}
		if result != "192.168.1.100" {
			t.Errorf("Expected fallback to RemoteAddr, got %q", result)
		}
	})
}
