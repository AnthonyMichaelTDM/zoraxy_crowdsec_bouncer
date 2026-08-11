SHELL := /bin/bash

COMPOSE ?= docker compose
PLUGIN_BIN := zoraxycrowdsecbouncer
PLUGIN_DIR := build/plugins/$(PLUGIN_BIN)
PLUGIN_PATH := $(PLUGIN_DIR)/$(PLUGIN_BIN)
PLUGIN_CONFIG := $(PLUGIN_DIR)/config.yaml
CROWDSEC_KEY_FILE := build/crowdsec/$(PLUGIN_BIN).apikey
CROWDSEC_BOUNCER_NAME ?= zoraxy-crowdsec-bouncer-local

.DEFAULT_GOAL := help

.PHONY: help
.PHONY: test vet
.PHONY: test-env-onboarding test-env-ready
.PHONY: test-env-up test-env-down test-env-logs test-env-status
.PHONY: test-env-dirs test-env-build test-env-restart-zoraxy
.PHONY: test-env-config-onboarding test-env-api-key test-env-config-ready
.PHONY: test-env-zoraxy-proxy-rule test-env-zoraxy-plugin-groups test-env-zoraxy-config

help:
	@echo "Available targets:"
	@echo "  make test                 - Run go test ./..."
	@echo "  make vet                  - Run go vet ./..."
	@echo "  make test-env-onboarding  - Build plugin + start compose + onboarding config (api_key unset)"
	@echo "  make test-env-ready       - Build plugin + start compose + auto-create CrowdSec key + ready config"
	@echo "  make test-env-up          - Build plugin and bring up compose stack"
	@echo "  make test-env-down        - Stop and remove compose stack"
	@echo "  make test-env-logs        - Tail compose logs"
	@echo "  make test-env-status      - Show key local endpoints"

test:
	go test ./...

vet:
	go vet ./...

test-env-onboarding: test-env-up test-env-config-onboarding test-env-zoraxy-config test-env-restart-zoraxy test-env-status

test-env-ready: test-env-up test-env-api-key test-env-config-ready test-env-zoraxy-config test-env-restart-zoraxy test-env-status

test-env-up: test-env-build
	$(COMPOSE) up -d crowdsec test_webserver zoraxy

test-env-down:
	$(COMPOSE) down

test-env-logs:
	$(COMPOSE) logs -f

test-env-status:
	@echo "Zoraxy UI: http://localhost:8000"
	@echo "Test route through Zoraxy: https://localhost:8443"
	@echo "Direct upstream through compose network: http://test_webserver:5678"
	@echo "Plugin config path: $(PLUGIN_CONFIG)"

test-env-dirs:
	mkdir -p "$(PLUGIN_DIR)"
	mkdir -p build/config
	mkdir -p build/config/conf/proxy
	mkdir -p build/crowdsec/config
	mkdir -p build/crowdsec/data

test-env-build: test-env-dirs
	go build -o "$(PLUGIN_PATH)" .
	chmod +x "$(PLUGIN_PATH)"

test-env-config-onboarding: test-env-dirs
	@printf '%s\n' \
		'# Crowdsec Bouncer Configuration' \
		'# api_key: "YOUR_CROWDSEC_BOUNCER_API_KEY"' \
		'agent_url: http://crowdsec:8080' \
		'stream_update_frequency: 10s' \
		'log_level: warning' \
		'is_proxied_behind_cloudflare: true' \
		> "$(PLUGIN_CONFIG)"
	@echo "Wrote onboarding config to $(PLUGIN_CONFIG)"

test-env-api-key:
	@echo "Waiting for CrowdSec Local API to become ready..."
	@ready=0; \
	for i in $$(seq 1 30); do \
		if $(COMPOSE) exec -T crowdsec cscli lapi status >/dev/null 2>&1; then \
			ready=1; \
			break; \
		fi; \
		sleep 1; \
	done; \
	if [[ $$ready -ne 1 ]]; then \
		echo "CrowdSec did not become ready in time"; \
		exit 1; \
	fi
	@$(COMPOSE) exec -T crowdsec cscli bouncers delete "$(CROWDSEC_BOUNCER_NAME)" >/dev/null 2>&1 || true
	@key="$$($(COMPOSE) exec -T crowdsec cscli bouncers add "$(CROWDSEC_BOUNCER_NAME)" -o raw 2>/dev/null)"; \
	if [[ -z "$$key" ]]; then \
		echo "Failed to generate CrowdSec bouncer API key"; \
		exit 1; \
	fi; \
	printf "%s" "$$key" > "$(CROWDSEC_KEY_FILE)"
	@echo "Saved CrowdSec API key to $(CROWDSEC_KEY_FILE)"

test-env-config-ready: test-env-dirs test-env-api-key
	@test -s "$(CROWDSEC_KEY_FILE)" || (echo "Missing API key file: $(CROWDSEC_KEY_FILE)" && exit 1)
	@api_key="$$(cat "$(CROWDSEC_KEY_FILE)")"; \
	printf '%s\n' \
		'# Crowdsec Bouncer Configuration' \
		"api_key: $$api_key" \
		'agent_url: http://crowdsec:8080' \
		'stream_update_frequency: 10s' \
		'log_level: warning' \
		'is_proxied_behind_cloudflare: true' \
		> "$(PLUGIN_CONFIG)"
	@echo "Wrote ready config to $(PLUGIN_CONFIG)"

test-env-restart-zoraxy:
	$(COMPOSE) restart zoraxy

# These targets are used to generate some of the config files that Zoraxy expects

test-env-jq-installed:
	@command -v jq >/dev/null 2>&1 || { echo "jq is required (please install jq)"; exit 1; }

test-env-zoraxy-proxy-rule: test-env-dirs jq-installed
	@printf '{"ProxyType": 1,"RootOrMatchingDomain": "localhost","ActiveOrigins": [{"OriginIpOrDomain": "crowdsec-bouncer-test-webserver:5678","RequireTLS": false,"SkipCertValidations": false,"SkipWebSocketOriginCheck": true,"Weight": 1,"MaxConn": 0,"RespTimeout": 0}],"TlsOptions": {"DisableSNI": false,"DisableLegacyCertificateMatching": false,"EnableAutoHTTPS": false,"PreferredCertificate": {}},"Tags": ["protected"]}' | jq . > build/config/conf/proxy/localhost.config
	@rm -f build/config/conf/proxy/crowdsec-bouncer-test-webserver.config

test-env-zoraxy-plugin-groups: test-env-dirs
	@printf '%s\n' '{"protected":["com.anthonyrubick.zoraxycrowdsecbouncer"]}' > build/config/conf/plugin_groups.json

test-env-zoraxy-config: test-env-zoraxy-proxy-rule test-env-zoraxy-plugin-groups 

.PHONY: install-hooks
install-hooks:
	command -v pre-commit >/dev/null 2>&1 || { echo "pre-commit is not installed. Install it with 'pip install pre-commit' or your package manager."; exit 1; }
	pre-commit install

