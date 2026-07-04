# Changelog

All notable changes to Taraqqub Shabaki are documented here.

## [1.0.0] - 2026-07-04

### Added

- Isolated workspaces for separate users and teams.
- Public signup switch with rate limiting.
- Outbound-only local network agent with explicit private `/24` scope.
- One-time, hashed, revocable agent tokens.
- Agent telemetry ingestion for devices, metrics, and alerts.
- Network Agent administration in the dashboard.
- Automated workspace-isolation and token-revocation tests.
- Hardened Docker image for the local agent.
- Responsive account and administration interfaces.

### Security

- Private IPv4 validation and a 256-device report limit.
- Agent report rate limiting.
- CSRF enforcement on agent administration.
- Demo discovery disabled for all roles.
- Non-root, capability-dropped server and agent containers.

### Deployment

- Public Render deployment remains a simulated, viewer-only demo.
- Production signup requires persistent storage.
