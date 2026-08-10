# Changelog

## v1.2.2

- Replaced per-request CrowdSec Local API queries with the CrowdSec decision stream.
- Added a concurrent in-memory cache for active IP and CIDR ban decisions.
- Added configurable stream update frequency, defaulting to 10 seconds.
- Retains the last known decision cache during temporary Local API update failures.
