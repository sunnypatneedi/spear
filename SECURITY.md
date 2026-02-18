# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (latest) | ✅ |

## Reporting a Vulnerability

Spear is a security tool — we take vulnerability reports seriously and respond quickly.

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately via one of these channels:

- **GitHub private vulnerability reporting**: [github.com/sunnypatneedi/spear/security/advisories/new](https://github.com/sunnypatneedi/spear/security/advisories/new)
- **Email**: open a GitHub Advisory and we'll respond within 48 hours

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional but appreciated)

### What to expect

- **Acknowledgement within 48 hours**
- **Triage within 5 business days**
- **Fix + coordinated disclosure** for confirmed vulnerabilities
- Credit in the changelog and advisory (unless you prefer to remain anonymous)

## Scope

In scope:

- Bypass of any Spear gate (InputGate, InstructionShield, ToolMediator, OutputGate)
- PII leaks through the sanitization pipeline
- Canary detection failures that allow exfiltration
- Policy parsing vulnerabilities (e.g. YAML injection)
- Dependency vulnerabilities with direct exploitability

Out of scope:

- Social engineering attacks
- Attacks requiring physical access
- Issues in transitive dependencies with no exploitable path
- "This gate can be bypassed if you disable it" (don't disable gates in production)
