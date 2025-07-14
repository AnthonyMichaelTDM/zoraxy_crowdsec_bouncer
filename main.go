package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"

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
	APIKey   string `yaml:"api_key"`
	AgentUrl string `yaml:"agent_url"`
	Debug    bool   `yaml:"debug"`
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
	// load the configuration, we do this first in case there are any errors
	config := &PluginConfig{}
	if err := config.loadConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

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
		VersionPatch:  0,

		DynamicCaptureSniff:   DYNAMIC_CAPTURE_SNIFF,
		DynamicCaptureIngress: DYNAMIC_CAPTURE_INGRESS,

		UIPath: UI_PATH,
	})
	if err != nil {
		//Terminate or enter standalone mode here
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
	pathRouter.SetDebugPrintMode(true)

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

func GetRealIP(dsfr *plugin.DynamicSniffForwardRequest) string {
	// Get the real IP address from the request
	realIP := dsfr.RemoteAddr
	if ip := dsfr.GetRequest().Header.Get("X-Real-IP"); ip != "" {
		realIP = ip
	}
	return realIP
}

// The Sniff handler is what decides whether to accept or skip a request
// It is called for each request
//
// TODO: if/when we support captchas, we should maybe add a header to the request, or something
func SniffHandler(config *PluginConfig, dsfr *plugin.DynamicSniffForwardRequest, bouncer *csbouncer.LiveBouncer) plugin.SniffResult {
	// Check if the request has a response in the bouncer
	ctx := context.Background()
	response, err := bouncer.Get(ctx, GetRealIP(dsfr))
	if err != nil {
		fmt.Println("Error getting decisions:", err)
		return plugin.SniffResultSkip // Skip the request if there is an error
	}
	if len(*response) == 0 {
		fmt.Println("No decision found for IP:", GetRealIP(dsfr))
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
	fmt.Println("Decision found for IP: ", GetRealIP(dsfr))
	return plugin.SniffResultAccpet // Accept the request to be handled by the Capture handler)
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

	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("Forbidden"))
	fmt.Println("Request forbidden:", r.RequestURI)
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
			fmt.Fprintf(w, "%s: %s\n", name, value)
		}
	}
	w.Header().Set("Content-Type", "text/html")
}
