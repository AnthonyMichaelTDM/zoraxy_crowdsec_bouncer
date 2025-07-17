package utils

import (
	"maps"
	"testing"

	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/sirupsen/logrus"
)

const LOG_LEVEL = logrus.WarnLevel

func TestGetRealIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string][]string
		isProxied  bool
		expected   string
	}{
		{
			name:       "Basic IP without headers",
			remoteAddr: "192.168.1.100",
			headers:    map[string][]string{},
			isProxied:  false,
			expected:   "192.168.1.100",
		},
		{
			name:       "IP with port, no headers",
			remoteAddr: "192.168.1.100:8080",
			headers:    map[string][]string{},
			isProxied:  false,
			expected:   "192.168.1.100",
		},
		{
			name:       "IPv6 with port",
			remoteAddr: "[2001:db8::1]:8080",
			headers:    map[string][]string{},
			isProxied:  false,
			expected:   "2001:db8::1",
		},
		{
			name:       "X-Real-IP header takes precedence",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string][]string{
				"X-Real-IP": {"10.0.0.5"},
			},
			isProxied: false,
			expected:  "10.0.0.5",
		},
		{
			name:       "X-Real-IP with port",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string][]string{
				"X-Real-IP": {"10.0.0.5:9090"},
			},
			isProxied: false,
			expected:  "10.0.0.5",
		},
		{
			name:       "CF-Connecting-IP when X-Real-IP is empty",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string][]string{
				"X-Real-IP":        {""},
				"CF-Connecting-IP": {"203.0.113.10"},
			},
			isProxied: true,
			expected:  "203.0.113.10",
		},
		{
			name:       "CF-Connecting-IP when X-Real-IP is nil",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string][]string{
				"X-Real-IP":        nil,
				"CF-Connecting-IP": {"203.0.113.10"},
			},
			isProxied: true,
			expected:  "203.0.113.10",
		},
		{
			name:       "CF-Connecting-IP with port",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string][]string{
				"CF-Connecting-IP": {"203.0.113.10:443"},
			},
			isProxied: true,
			expected:  "203.0.113.10",
		},
		{
			name:       "CF-Connecting-IP with port, different casing",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string][]string{
				"cf-connecting-ip": {"203.0.113.10:443"},
			},
			isProxied: true,
			expected:  "203.0.113.10",
		},
		{
			name:       "X-Real-IP takes precedence over CF-Connecting-IP",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string][]string{
				"X-Real-IP":        {"10.0.0.5"},
				"CF-Connecting-IP": {"203.0.113.10"},
			},
			isProxied: true,
			expected:  "10.0.0.5",
		},
		{
			name:       "CF-Connecting-IP takes precedence over X-Forwarded-For",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string][]string{
				"CF-Connecting-IP": {"203.0.113.10"},
				"X-Forwarded-For":  {"1.2.3.4"},
			},
			isProxied: true,
			expected:  "203.0.113.10",
		},
		{
			name:       "Multiple colons in IPv6 address",
			remoteAddr: "2001:db8:85a3:8d3:1319:8a2e:370:7348",
			headers:    map[string][]string{},
			isProxied:  false,
			expected:   "2001:db8:85a3:8d3:1319:8a2e:370:7348",
		},
		{
			name:       "Header with IPv6",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string][]string{
				"X-Real-IP": {"2001:db8::1"},
			},
			isProxied: false,
			expected:  "2001:db8::1",
		},
		{
			name:       "Header with IPv6 and port",
			remoteAddr: "192.168.1.100:8080",
			headers: map[string][]string{
				"X-Real-IP": {"[2001:db8::1]:443"},
			},
			isProxied: false,
			expected:  "2001:db8::1",
		},
		{
			name:       "X-Forwarded-For with multiple IPs",
			remoteAddr: "",
			headers: map[string][]string{
				"X-Forwarded-For": {"1.2.3.4", "5.6.7.8"},
			},
			isProxied: false,
			expected:  "1.2.3.4",
		},
		{
			name:       "X-Forwarded-For with multiple IPs one string",
			remoteAddr: "",
			headers: map[string][]string{
				"X-Forwarded-For": {"1.2.3.4, 5.6.7.8"},
			},
			isProxied: false,
			expected:  "1.2.3.4",
		},
		{
			name:       "X-Forwarded-For with single IP",
			remoteAddr: "",
			headers: map[string][]string{
				"X-Forwarded-For": {"1.2.3.4"},
			},
			isProxied: false,
			expected:  "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock DynamicSniffForwardRequest
			dsfr := &plugin.DynamicSniffForwardRequest{
				RemoteAddr: tt.remoteAddr,
				Header:     make(map[string][]string),
			}
			maps.Copy(dsfr.Header, tt.headers)

			// Create a logger
			logger := logrus.StandardLogger()
			logger.SetLevel(LOG_LEVEL)

			// Call the function
			result, err := GetRealIP(logger, dsfr, tt.isProxied)
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
	dsfr := &plugin.DynamicSniffForwardRequest{
		RemoteAddr: "192.168.1.100:8080",
		Header:     map[string][]string{"X-Real-IP": {"10.0.0.5"}},
	}

	// Create a logger
	logger := logrus.StandardLogger()
	logger.SetLevel(LOG_LEVEL)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetRealIP(logger, dsfr, false)
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

		// Create a logger
		logger := logrus.StandardLogger()
		logger.SetLevel(LOG_LEVEL)

		result, err := GetRealIP(logger, dsfr, false)
		if err != nil {
			t.Errorf("GetRealIP returned an error: %v", err)
		}
		if result != "192.168.1.100" {
			t.Errorf("Expected fallback to RemoteAddr, got %q", result)
		}
	})
}
