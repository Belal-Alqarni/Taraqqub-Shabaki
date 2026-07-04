# Security Policy

## Supported Version

Security fixes are applied to the latest commit on the `main` branch.

## Reporting a Vulnerability

Please do not publish sensitive vulnerability details in a public issue.
Instead, use GitHub's private vulnerability reporting feature for this
repository. Include reproduction steps, affected endpoints, expected impact,
and any suggested remediation.

Do not test discovery or remediation features against infrastructure you do not
own or have explicit authorization to assess.

## Public Demo Boundary

The public demo uses simulated infrastructure. Network discovery is disabled
for every account, including administrators. Real network collection runs
through the outbound-only local agent.

## Network Agent

- Configure only a private IPv4 subnet you own or are authorized to monitor.
- Treat the one-time agent token like a password and never commit it to Git.
- The agent connects outbound to the control plane; do not expose agent ports.
- Revoke a token immediately if its host is lost or compromised.
- Public control-plane deployments must use HTTPS.
