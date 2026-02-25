"""
Snapwire Community Rules — Deterministic Firewall Rules

Each rule in this directory implements a single, deterministic safety check
that runs before an agent tool call is executed. Rules don't use AI judgment;
they enforce hard mathematical limits.

To contribute a new rule:
1. Fork the repo
2. Copy any stub file as a starting point
3. Implement the `evaluate()` function
4. Submit a PR

See CONTRIBUTING.md for full guidelines.
"""
