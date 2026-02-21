# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Snapwire, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, send an email to **security@snapwire.dev** with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. The potential impact
4. Any suggested fixes (optional)

## Response Timeline

- **Acknowledgment**: Within 48 hours of receiving your report
- **Initial Assessment**: Within 5 business days
- **Resolution Target**: Critical vulnerabilities within 14 days, others within 30 days

## Scope

The following are in scope for security reports:

- Authentication and authorization bypass
- Snap-Token generation, storage, or revocation flaws
- Identity Vault credential leakage
- SQL injection or other injection attacks
- Cross-site scripting (XSS) in the dashboard
- Server-side request forgery (SSRF)
- Privilege escalation between tenants
- Data exposure across tenant boundaries

## Out of Scope

- Denial of service attacks
- Social engineering
- Issues in third-party dependencies (report those upstream)
- Vulnerabilities requiring physical access

## Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations and data destruction
- Only interact with accounts they own or have explicit permission to test
- Do not exploit a vulnerability beyond what is necessary to confirm it
- Report vulnerabilities promptly

## Recognition

We maintain a list of security researchers who have responsibly disclosed vulnerabilities. If you would like to be credited, please let us know in your report.
