package info

const (
	PLUGIN_ID               = "com.anthonyrubick.zoraxycrowdsecbouncer"
	PLUGIN_NAME             = "Crowdsec Bouncer Plugin for Zoraxy"
	PLUGIN_AUTHOR           = "Anthony Rubick"
	PLUGIN_AUTHOR_CONTACT   = "https://github.com/AnthonyMichaelTDM"
	PLUGIN_DESCRIPTION      = "This plugin is a Crowdsec bouncer for Zoraxy. It will block requests based on Crowdsec decisions."
	PLUGIN_URL              = "https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer"
	UI_PATH                 = "/"
	WEB_ROOT                = "/www"
	API_PATH                = "/api"
	DYNAMIC_CAPTURE_INGRESS = "/d_capture"
	DYNAMIC_CAPTURE_SNIFF   = "/d_sniff"
	CONFIGURATION_FILE      = "./config.yaml"
	BOUNCER_TYPE            = "zoraxy-crowdsec-bouncer"

	VERSION_MAJOR  = 1
	VERSION_MINOR  = 2
	VERSION_PATCH  = 2
	VERSION_STRING = "v1.2.2"

	// BOUNCER_USER_AGENT must use the name/version format expected by CrowdSec's LAPI.
	BOUNCER_USER_AGENT = BOUNCER_TYPE + "/" + VERSION_STRING
)
