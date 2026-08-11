# Changelog

## Unreleased

- Updated local test environment documentation and proxy rule generation for browser testing through Zoraxy at https://localhost:8443 by @AnthonyMichaelTDM.

## v1.2.2

- Updated dependencies to address security vulnerabilities by @AnthonyMichaelTDM in #37.
- Updated the bouncer's user agent to match the CrowdSec Local API's expected format by @paddy73-ch in #36.
- Replaced per-request CrowdSec Local API queries with the CrowdSec decision stream by @paddy73-ch in #35.
- Added a concurrent in-memory cache for active IP and CIDR ban decisions by @paddy73-ch in #35.
- Added configurable stream update frequency, defaulting to 10 seconds by @paddy73-ch in #35.
- Retained the last known decision cache during temporary Local API update failures by @paddy73-ch in #35.

## v1.2.1

- Reworked the embedded web UI into a dedicated web module with an API-backed server by @AnthonyMichaelTDM in #11.
- Added a standalone development web server tool for UI work by @AnthonyMichaelTDM in #11.
- Improved shutdown behavior and refactored plugin configuration, dynamic capture, and signal handling into separate modules by @AnthonyMichaelTDM in #11.
- Updated the UI styling and fixed the font mismatch between the plugin and the Zoraxy dashboard by @AnthonyMichaelTDM in #13.
- Added CI workflow improvements, including linting, concurrency controls, and explicit permissions by @AnthonyMichaelTDM in #16.
- Updated documentation and dependency versions by @dependabot[bot] in #14.

## v1.2.0

- Added a basic metrics dashboard and theme-aware web UI by @AnthonyMichaelTDM in #5.
- Added a version check with rate limiting by @AnthonyMichaelTDM in #10.
- Fixed origin label handling in the web UI by @AnthonyMichaelTDM in #6.
- Improved the web UI theme integration with the Zoraxy dashboard by @AnthonyMichaelTDM in #6.
- Expanded the README and Web UI documentation by @AnthonyMichaelTDM in #9.

## v1.1.1

- Improved the web UI and added update-check support by @AnthonyMichaelTDM in #4.
- Reduced log verbosity for unknown metrics by @AnthonyMichaelTDM in #3.

## v1.1.0

- Updated release documentation and README details for the 1.1 series by @AnthonyMichaelTDM.

## v1.0.5

- Added metrics handling and Prometheus integration by @AnthonyMichaelTDM in #1.
- Added structured logging and improved debug-mode behavior by @AnthonyMichaelTDM in #1.
- Integrated metrics support into dynamic capture endpoints by @AnthonyMichaelTDM in #1.
- Updated installation and configuration documentation by @AnthonyMichaelTDM in #1.

## v1.0.4

- Improved client IP extraction logic for forwarded request headers by @AnthonyMichaelTDM.
- Reduced logging noise in normal operation by @AnthonyMichaelTDM.

## v1.0.3

- Improved IP extraction fallback behavior for X-Forwarded-For headers by @AnthonyMichaelTDM.

## v1.0.2

- Further improved real IP detection and error handling for forwarded requests by @AnthonyMichaelTDM.

## v1.0.1

- Fixed startup ordering so the configuration is loaded before serving introspection endpoints by @AnthonyMichaelTDM.

## v1.0.0

- Initial public release of the CrowdSec bouncer plugin with installation guidance, configuration support, and core blocking functionality by @AnthonyMichaelTDM.
