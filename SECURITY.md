# Security Policy

## Reporting a Vulnerability

The Physarum team takes security issues seriously. We appreciate your
efforts to responsibly disclose your findings, and will make every
effort to acknowledge your contributions.

### Where to report

**Do not open public GitHub issues for security vulnerabilities.**

Please report security issues by email to:

    fabio.schorn@expertsonline.com.br

Or use GitHub's private vulnerability reporting feature on this
repository (Security tab → Report a vulnerability).

### What to include

Please include the following information in your report:

- Type of issue (e.g., authentication bypass, signature forgery,
  side-channel leak, denial-of-service, supply-chain risk)
- Full paths of source files related to the issue
- Location of the affected source code (tag, branch, commit, or URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code, if available
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report quickly.

### Disclosure timeline

We follow a coordinated disclosure model:

- **Day 0**: We acknowledge receipt within 48 hours.
- **Day 1-7**: We confirm the issue and determine its severity.
- **Day 7-30**: We develop and test a fix.
- **Day 30-90**: We coordinate disclosure with affected parties and
  release a patched version.
- **Day 90+**: Public disclosure, with credit to the reporter (if
  desired).

Severity-1 issues (active exploitation in the wild, full system
compromise) accelerate this timeline. Severity-3 issues (theoretical,
hard-to-exploit) may take longer.

## Supported Versions

This project is in research-prototype stage. Until a stable 1.0
release is published, security fixes are applied to the `main` branch
only. Production deployments before 1.0 are not recommended.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| < 1.0   | :x:                |

## Threat Model Scope

The threats actively addressed by Physarum's design are documented in
[`docs/threat-model.md`](./docs/threat-model.md). Out-of-scope threats
include:

- Compromise of the agent host kernel (eBPF observations cannot be
  trusted on a rooted host)
- Denial-of-service of the coordinator (handled at deployment layer)
- Side-channel inference of network topology by passive observers

Reports falling outside these boundaries are still welcome but may
not result in a code change.

## Hall of Fame

Contributors who report valid security issues will be acknowledged
here, with their permission.

*(none yet)*