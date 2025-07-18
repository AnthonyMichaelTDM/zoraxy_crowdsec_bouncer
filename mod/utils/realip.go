package utils

import (
	"fmt"
	"net"
	"strings"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/sirupsen/logrus"
)

// GetRealIP extracts the real IP address from the request headers.
// It checks for the `X-Real-IP`, `CF-Connecting-IP`, and `X-Forwarded-For` headers
//
// # Arguments:
//   - dsfr: The DynamicSniffForwardRequest object containing the request headers and remote
//   - isProxiedBehindCloudflare: If true, it will prioritize the `CF-Connecting-IP` header
//   - debug: If true, it will print extra debug information to the console
func GetRealIP(logger *logrus.Logger, dsfr *zoraxy_plugin.DynamicSniffForwardRequest, isProxiedBehindCloudflare bool) (string, error) {
	// Get the real IP address from the request
	realIP := ""

	// Check for the `X-Real-IP`, `CF-Connecting-IP`, and `X-Forwarded-For` headers
	if headers := dsfr.Header; headers != nil {
		// Check for X-Real-IP header, we don't really expect to see this so we won't log an error if it is not found
		X_Real_IP, err := ExtractHeader(headers, "X-Real-IP", false)
		if err == nil && X_Real_IP != "" {
			// Use X-Real-IP header
			realIP = X_Real_IP
			goto IPFound
		}

		// Check for CF-Connecting-IP header
		CF_Connecting_IP, err := ExtractHeader(headers, "CF-Connecting-IP", isProxiedBehindCloudflare)
		if err != nil && isProxiedBehindCloudflare {
			logger.Debugf("GetRealIP failed to extract CF-Connecting-IP for request with UUID %s: %v", dsfr.GetRequestUUID(), err)
		} else if CF_Connecting_IP == "" {
			logger.Debugf("GetRealIP got an empty string for CF-Connecting-IP for request with UUID %s", dsfr.GetRequestUUID())
		} else if CF_Connecting_IP != "" {
			// Use CF Connecting IP
			realIP = CF_Connecting_IP
			goto IPFound
		}

		// Check for X-Forwarded-For header
		// We take the first IP in the list, as it is the original client IP
		X_Forwarded_For, err := ExtractHeader(headers, "X-Forwarded-For", true)
		if err != nil {
			logger.Debugf("GetRealIP failed to extract X-Forwarded-For for request with UUID %s: %v", dsfr.GetRequestUUID(), err)
		} else if X_Forwarded_For == "" {
			logger.Debugf("GetRealIP got an empty string for X-Forwarded-For for request with UUID %s", dsfr.GetRequestUUID())
		} else if X_Forwarded_For != "" {
			// Use X-Forwarded-For header
			// We take the first IP in the list, as it is the original client IP
			ips := strings.Split(X_Forwarded_For, ",")
			if len(ips) > 0 {
				realIP = strings.TrimSpace(ips[0])
			}
			goto IPFound
		}
	}
	// If no headers are found, we will use the RemoteAddr, if it is not empty
	if dsfr.RemoteAddr != "" {
		logger.Debugf("GetRealIP using RemoteAddr for request with UUID %s: %s", dsfr.GetRequestUUID(), dsfr.RemoteAddr)
		realIP = dsfr.RemoteAddr
	} else {
		return "", fmt.Errorf("no valid IP address found in headers")
	}
IPFound:
	realIP = strings.TrimSpace(realIP)

	// extract the IP address from what is potentially a host:port format
	ip, _, err := net.SplitHostPort(realIP)
	if err != nil {
		// If SplitHostPort fails, it means there is no port, so we can use the whole string as the IP
		ip = realIP
	}

	// Validate the IP address
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	return ip, nil
}
