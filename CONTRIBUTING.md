# Contributing to Snapwire

Snapwire is the deterministic circuit breaker for AI agents. We welcome contributions that make autonomous AI safer for everyone.

## Quick Start

1. Fork the repository
2. Clone your fork locally
3. Run with Docker:
   ```bash
   docker-compose up
   ```
4. The app will be available at `http://localhost:5000`

## What We're Looking For

### Custom Deterministic Rules

The core value of Snapwire is **deterministic safety** — hard mathematical limits that don't rely on AI judgment. We welcome new rules that follow this pattern:

- **Loop detection rules**: New patterns for catching agent misbehavior (the existing 3x/30s rule is in `src/loop_detector.py`)
- **Schema validation rules**: Per-tool JSON schemas that enforce safe parameter boundaries (see `src/schema_guard.py`)
- **Blast radius rules**: New limit types for constraining agent behavior (see `src/blast_radius.py`)

### Bug Fixes and Improvements

- Security hardening
- Performance improvements for high-frequency agent tool calls
- Dashboard UI improvements
- Documentation and examples

## Development Setup

### Prerequisites

- Python 3.11+
- PostgreSQL (or use the Docker setup)

### Local Setup

```bash
pip install -e .
export DATABASE_URL="postgresql://user:pass@localhost:5432/snapwire"
export SESSION_SECRET="dev-secret"
python main.py
```

### Running Tests

```bash
python -m pytest tests/ -v
```

## Pull Request Guidelines

1. **One feature per PR** — keep changes focused and reviewable
2. **Include tests** — especially for new deterministic rules
3. **Don't break existing rules** — the 3x/30s fuse and existing schema guards must continue to pass
4. **Update documentation** — if you add a new rule type, document it
5. **Follow existing code style** — match the patterns in neighboring files

## Architecture Overview

| Component | File | Purpose |
|---|---|---|
| Loop Detector | `src/loop_detector.py` | Deterministic 3x/30s fuse breaker |
| Schema Guard | `src/schema_guard.py` | Per-tool JSON schema enforcement |
| Blast Radius | `src/blast_radius.py` | Per-agent spending/action limits |
| Risk Index | `src/risk_index.py` | 0-100 trust scoring per tool |
| Identity Vault | `src/vault.py` | Snap-Token proxy credential system |
| Tool Catalog | `src/tool_catalog.py` | AI-powered tool safety grading |
| Intercept API | `main.py` | Main gateway endpoint |

## Code of Conduct

Be respectful, constructive, and focused on making AI agents safer. We're building critical safety infrastructure — treat contributions accordingly.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
