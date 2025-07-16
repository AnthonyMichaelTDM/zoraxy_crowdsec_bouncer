package main

import (
	"context"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"gopkg.in/yaml.v2"
)

const (
	PLUGIN_ID               = "com.anthonyrubick.zoraxycrowdsecbouncer"
	UI_PATH                 = "/debug"
	DYNAMIC_CAPTURE_INGRESS = "/d_capture"
	DYNAMIC_CAPTURE_SNIFF   = "/d_sniff"
	CONFIGURATION_FILE      = "./config.yaml"
)

type PluginConfig struct {
	APIKey                    string `yaml:"api_key"`
	AgentUrl                  string `yaml:"agent_url"`
	Debug                     bool   `yaml:"debug"`
	IsProxiedBehindCloudflare bool   `yaml:"is_proxied_behind_cloudflare"`
}

func (p *PluginConfig) loadConfig() error {
	configFile, err := os.Open(CONFIGURATION_FILE)
	if err != nil {
		return fmt.Errorf("unable to open config file: %w", err)
	}
	defer configFile.Close()

	content, err := io.ReadAll(configFile)
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}

	err = yaml.Unmarshal(content, p)
	if err != nil {
		return fmt.Errorf("unable to unmarshal config file: %w", err)
	}

	return nil
}

func main() {
	// Serve the plugin introspect
	// This will print the plugin introspect and exit if the -introspect flag is provided
	runtimeCfg, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:            PLUGIN_ID,
		Name:          "Crowdsec Bouncer Plugin for Zoraxy",
		Author:        "Anthony Rubick",
		AuthorContact: "",
		Description:   "This plugin is a Crowdsec bouncer for Zoraxy. It will block requests based on Crowdsec decisions.",
		URL:           "https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer",
		Type:          plugin.PluginType_Router,
		VersionMajor:  1,
		VersionMinor:  0,
		VersionPatch:  4,

		DynamicCaptureSniff:   DYNAMIC_CAPTURE_SNIFF,
		DynamicCaptureIngress: DYNAMIC_CAPTURE_INGRESS,

		UIPath: UI_PATH,
	})
	if err != nil {
		//Terminate or enter standalone mode here
		panic(err)
	}

	// load the configuration, we do this first in case there are any errors
	config := &PluginConfig{}
	if err := config.loadConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		panic(err)
	}

	// Initialize the Crowdsec bouncer
	bouncer := &csbouncer.LiveBouncer{
		APIKey:    config.APIKey,
		APIUrl:    config.AgentUrl,
		UserAgent: "zoraxy-crowdsec-bouncer",
	}
	if err := bouncer.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "unable to initialize bouncer: %v\n", err)
		os.Exit(1)
	}

	// Setup the path router
	pathRouter := plugin.NewPathRouter()
	pathRouter.SetDebugPrintMode(config.Debug)

	/*
		Dynamic Captures

		If there is not a decision matching the requests IP, we will skip the request so
		that it can be handled by the next plugin or Zoraxy itself.
		If there is a decision for the request IP, we will accept the request and handle it in the dynamic capture handler.
		We will also print the request information to the console for debugging purposes.
	*/
	pathRouter.RegisterDynamicSniffHandler("/d_sniff", http.DefaultServeMux, func(dsfr *plugin.DynamicSniffForwardRequest) plugin.SniffResult {
		return SniffHandler(config, dsfr, bouncer)
	})
	pathRouter.RegisterDynamicCaptureHandle(DYNAMIC_CAPTURE_INGRESS, http.DefaultServeMux, func(w http.ResponseWriter, r *http.Request) {
		CaptureHandler(config, w, r)
	})
	http.HandleFunc(UI_PATH+"/", RenderDebugUI)

	fmt.Println("Zoraxy Crowdsec Bouncer started at http://127.0.0.1:" + strconv.Itoa(runtimeCfg.Port))
	http.ListenAndServe("127.0.0.1:"+strconv.Itoa(runtimeCfg.Port), nil)
}

// ExtractHeader extracts the values of a header from the request headers map
// If the header is not found, behavior depends on the searchIfNotFound flag:
//   - If true, will search all the keys in the headers map to find a case-insensitive match
//   - If false, will return an empty string
func ExtractHeader(headers map[string][]string, key string, searchIfNotFound bool) (string, error) {
	// first, try accessing the header directly
	if values, ok := headers[key]; ok {
		if concattenated := strings.Join(values, ", "); concattenated != "" {
			return concattenated, nil
		} else {
			return "", fmt.Errorf("header %s found but has no values", key)
		}
	}

	if searchIfNotFound {
		// If not found, search for a case-insensitive match
		for k, v := range headers {
			if strings.EqualFold(k, key) && len(v) > 0 {
				return strings.Join(v, ", "), nil
			}
		}
	}

	return "", fmt.Errorf("header %s not found", key)
}

// GetRealIP extracts the real IP address from the request headers.
// It checks for the `X-Real-IP`, `CF-Connecting-IP`, and `X-Forwarded-For` headers
//
// # Arguments:
//   - dsfr: The DynamicSniffForwardRequest object containing the request headers and remote
//   - isProxiedBehindCloudflare: If true, it will prioritize the `CF-Connecting-IP` header
//   - debug: If true, it will print extra debug information to the console
func GetRealIP(dsfr *plugin.DynamicSniffForwardRequest, isProxiedBehindCloudflare bool, debug bool) (string, error) {
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
		if err != nil && debug && isProxiedBehindCloudflare {
			fmt.Println("GetRealIP failed to extract CF-Connecting-IP for request with UUID", dsfr.GetRequestUUID(), ":", err)
		} else if CF_Connecting_IP == "" && debug {
			fmt.Println("GetRealIP got an empty string for CF-Connecting-IP for request with UUID", dsfr.GetRequestUUID())
		} else if CF_Connecting_IP != "" {
			// Use CF Connecting IP
			realIP = CF_Connecting_IP
			goto IPFound
		}

		// Check for X-Forwarded-For header
		// We take the first IP in the list, as it is the original client IP
		X_Forwarded_For, err := ExtractHeader(headers, "X-Forwarded-For", true)
		if err != nil && debug {
			fmt.Println("GetRealIP failed to extract X-Forwarded-For for request with UUID", dsfr.GetRequestUUID(), ":", err)
		} else if X_Forwarded_For == "" && debug {
			fmt.Println("GetRealIP got an empty string for X-Forwarded-For for request with UUID", dsfr.GetRequestUUID())
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
		if debug {
			fmt.Println("GetRealIP using RemoteAddr for request with UUID", dsfr.GetRequestUUID(), ":", dsfr.RemoteAddr)
		}
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

// The Sniff handler is what decides whether to accept or skip a request
// It is called for each request
//
// TODO: if/when we support captchas, we should maybe add a header to the request, or something
func SniffHandler(config *PluginConfig, dsfr *plugin.DynamicSniffForwardRequest, bouncer *csbouncer.LiveBouncer) plugin.SniffResult {
	// Check if the request has a response in the bouncer
	ctx := context.Background()
	ip, err := GetRealIP(dsfr, config.IsProxiedBehindCloudflare, config.Debug)
	if err != nil {
		fmt.Println("GetRealIP Got an error: ", err, " for request: ", dsfr.GetRequest().RequestURI)
		return plugin.SniffResultSkip // Skip the request if there is an error
	}

	response, err := bouncer.Get(ctx, ip)
	if err != nil {
		fmt.Println("Error getting decisions:", err)
		return plugin.SniffResultSkip // Skip the request if there is an error
	}
	if len(*response) == 0 {
		if config.Debug {
			fmt.Println("No decision found for IP:", ip)
		}
		return plugin.SniffResultSkip // Skip the request if there is no decision
	}

	// Print the decisions for debugging
	if config.Debug {
		for _, decision := range *response {
			fmt.Printf("decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		}
	}

	// Since we have a decision, and this is a naive bouncer, we
	// will ban all requests that have a decision
	if config.Debug {
		fmt.Println("Decision found for IP: ", ip)
	}
	return plugin.SniffResultAccept // Accept the request to be handled by the Capture handler)
}

// The Capture handler is what handles the requests that were accepted by the Sniff handler
// It is called for each request that was accepted by the Sniff handler.
//
// If the request was accepted, that means that there is a decision for the request IP,
//
// TODO: implement a way to present a captcha if the decision is to present a captcha
func CaptureHandler(config *PluginConfig, w http.ResponseWriter, r *http.Request) {
	// This is the dynamic capture handler where it actually captures and handle the request
	if config.Debug {
		fmt.Println("Dynamic capture handler called for request:", r.RequestURI)
	}

	// it would be really funny if we could return a 5 petabyte zip bomb or something,
	// but let's not...

	w.WriteHeader(http.StatusForbidden)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Forbidden"))
	fmt.Println("Request forbidden: ", r.RequestURI)
}

// Render the debug UI
func RenderDebugUI(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "**Zoraxy Crowdsec Bouncer UI Debug Interface**\n\n[Recv Headers] \n")

	headerKeys := make([]string, 0, len(r.Header))
	for name := range r.Header {
		headerKeys = append(headerKeys, name)
	}
	sort.Strings(headerKeys)
	for _, name := range headerKeys {
		values := r.Header[name]
		for _, value := range values {
			fmt.Fprintf(w, "%s: %s\n", name, html.EscapeString(value))
		}
	}
	w.Header().Set("Content-Type", "text/html")
}
