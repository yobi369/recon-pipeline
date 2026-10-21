# Security Policy

## Intended use
Recon Pipeline is for assets you own or have explicit written permission to assess. The --authorized flag is an operator acknowledgement, not proof of permission and not a mechanism for expanding a program's scope.

## Safe operation
- Confirm the exact domain and rules of engagement before every run.
- Start with default conservative settings.
- Enable TCP checks only when permitted and select only necessary ports.
- Treat DNS, HTTP status, and open-port results as observations, not confirmed vulnerabilities.
- Do not publish credentials or sensitive findings in public issues.

## Reporting
Use GitHub's private vulnerability reporting feature if enabled for this repository, or contact the maintainer privately.

## Limitations
Certificate Transparency data can be incomplete or stale. DNS and HTTP results are affected by filtering and network conditions. This release is a reconnaissance foundation, not a certified scanner or a substitute for professional security assessment.
