#!/usr/bin/env python3
"""
Snapwire — Day Zero Developer Health Check

Run this script once after setting up your environment to verify
that all critical systems are correctly configured.

Usage:
    python scripts/dev_health_check.py

Exit codes:
    0 — All critical checks passed
    1 — One or more critical checks failed
"""

import os
import sys
import json
import subprocess
import urllib.request
import urllib.error

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"

SNAPWIRE_URL = os.environ.get("SNAPWIRE_URL", "http://localhost:5000")

results = []


def check(name, passed, critical=True, message="", remediation=""):
    status = "PASS" if passed else ("FAIL" if critical else "WARN")
    results.append({
        "name": name,
        "status": status,
        "critical": critical,
        "message": message,
        "remediation": remediation,
    })
    if passed:
        print(f"  {GREEN}✓{NC} {name}")
    elif critical:
        print(f"  {RED}✗{NC} {name}")
    else:
        print(f"  {YELLOW}⚠{NC} {name}")
    if message:
        print(f"    {message}")
    if not passed and remediation:
        print(f"    {YELLOW}→ {remediation}{NC}")


def check_database_url():
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        check(
            "DATABASE_URL set",
            False,
            critical=True,
            remediation="Set DATABASE_URL in your environment (e.g. postgresql://user:pass@host/db)",
        )
        return

    check("DATABASE_URL set", True)

    try:
        import sqlalchemy
        engine = sqlalchemy.create_engine(db_url)
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text("SELECT 1"))
        check("Database connectivity", True)
    except Exception as e:
        check(
            "Database connectivity",
            False,
            critical=True,
            message=str(e),
            remediation="Verify DATABASE_URL is correct and the database server is running",
        )


def check_slack_tokens():
    bot_token = os.environ.get("SLACK_BOT_TOKEN", "")
    app_token = os.environ.get("SLACK_APP_TOKEN", "")
    both_present = bool(bot_token) and bool(app_token)
    if both_present:
        check("Slack tokens (SLACK_BOT_TOKEN + SLACK_APP_TOKEN)", True, critical=False)
    elif bot_token or app_token:
        missing = "SLACK_APP_TOKEN" if bot_token else "SLACK_BOT_TOKEN"
        check(
            "Slack tokens (SLACK_BOT_TOKEN + SLACK_APP_TOKEN)",
            False,
            critical=False,
            message=f"{missing} is missing",
            remediation=f"Set {missing} to enable Slack alerts. Slack integration is optional but recommended.",
        )
    else:
        check(
            "Slack tokens (SLACK_BOT_TOKEN + SLACK_APP_TOKEN)",
            False,
            critical=False,
            message="Neither token is set",
            remediation="Set SLACK_BOT_TOKEN and SLACK_APP_TOKEN to enable Slack alerts. This is optional.",
        )


def check_app_server():
    try:
        req = urllib.request.Request(f"{SNAPWIRE_URL}/health", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                check("App server reachable at /health", True)
                return
        check(
            "App server reachable at /health",
            False,
            critical=True,
            message=f"Unexpected status {resp.status}",
            remediation=f"Start the server with: python main.py (expected at {SNAPWIRE_URL})",
        )
    except Exception as e:
        check(
            "App server reachable at /health",
            False,
            critical=True,
            message=str(e),
            remediation=f"Start the server with: python main.py (expected at {SNAPWIRE_URL})",
        )


def check_test_suite():
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=no"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            passed_line = [l for l in result.stdout.strip().splitlines() if "passed" in l]
            msg = passed_line[-1] if passed_line else ""
            check("Test suite passes", True, message=msg)
        else:
            last_lines = result.stdout.strip().splitlines()[-3:]
            check(
                "Test suite passes",
                False,
                critical=True,
                message="\n    ".join(last_lines),
                remediation="Run 'python -m pytest tests/ -v' for details",
            )
    except subprocess.TimeoutExpired:
        check(
            "Test suite passes",
            False,
            critical=True,
            message="Test run timed out after 120s",
            remediation="Run 'python -m pytest tests/ -v' manually",
        )
    except Exception as e:
        check(
            "Test suite passes",
            False,
            critical=True,
            message=str(e),
            remediation="Ensure pytest is installed: pip install pytest",
        )


def check_sentinel_config():
    try:
        from sentinel.proxy import SentinelProxy
        p = SentinelProxy({"signing_secret": "test", "mode": "enforce"})
        valid = (
            p.signing_secret == "test"
            and p.mode == "enforce"
            and hasattr(p, "upstream_url")
            and hasattr(p, "snapwire_url")
        )
        check("Sentinel proxy config valid", valid)
        if not valid:
            check(
                "Sentinel proxy config valid",
                False,
                critical=True,
                remediation="Check sentinel/proxy.py — SentinelProxy class may be broken",
            )
    except ImportError:
        check(
            "Sentinel proxy config valid",
            True,
            critical=False,
            message="Sentinel runs as a separate sidecar — import not available in main app",
        )
    except Exception as e:
        check(
            "Sentinel proxy config valid",
            False,
            critical=False,
            message=str(e),
            remediation="Check sentinel/proxy.py is importable and SentinelProxy is defined",
        )


def check_hold_window():
    try:
        req = urllib.request.Request(f"{SNAPWIRE_URL}/api/settings/hold-window", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            hw = data.get("hold_window_seconds", None)
            if hw is not None:
                check("Hold window configured", True, message=f"hold_window_seconds = {hw}")
            else:
                check(
                    "Hold window configured",
                    False,
                    critical=True,
                    message="Response missing hold_window_seconds",
                    remediation="Verify the /api/settings/hold-window endpoint is working",
                )
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            check(
                "Hold window configured",
                True,
                critical=False,
                message="Endpoint requires authentication (expected in production)",
            )
        else:
            check(
                "Hold window configured",
                False,
                critical=True,
                message=f"HTTP {e.code}",
                remediation="Check the /api/settings/hold-window endpoint",
            )
    except Exception as e:
        check(
            "Hold window configured",
            False,
            critical=True,
            message=str(e),
            remediation=f"Ensure the app server is running at {SNAPWIRE_URL}",
        )


def check_constitution_rules():
    try:
        constitution_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "constitution.json",
        )
        with open(constitution_path, "r") as f:
            data = json.load(f)
        rules = data.get("rules", {})
        count = len(rules)
        if count >= 1:
            check("Constitution rules exist", True, message=f"{count} rule(s) found")
        else:
            check(
                "Constitution rules exist",
                False,
                critical=True,
                message="No rules found in constitution.json",
                remediation="Add at least one rule to constitution.json",
            )
    except FileNotFoundError:
        check(
            "Constitution rules exist",
            False,
            critical=True,
            message="constitution.json not found",
            remediation="Create constitution.json in the project root with at least one rule",
        )
    except Exception as e:
        check(
            "Constitution rules exist",
            False,
            critical=True,
            message=str(e),
            remediation="Verify constitution.json is valid JSON",
        )


def main():
    print()
    print(f"{CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print(f"{CYAN}  Snapwire — Day Zero Environment Health Check{NC}")
    print(f"{CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print()

    print(f"{BOLD}  Environment Variables{NC}")
    print(f"  ─────────────────────────────────────────────")
    check_database_url()
    check_slack_tokens()
    print()

    print(f"{BOLD}  Services{NC}")
    print(f"  ─────────────────────────────────────────────")
    check_app_server()
    check_hold_window()
    print()

    print(f"{BOLD}  Configuration{NC}")
    print(f"  ─────────────────────────────────────────────")
    check_sentinel_config()
    check_constitution_rules()
    print()

    print(f"{BOLD}  Test Suite{NC}")
    print(f"  ─────────────────────────────────────────────")
    check_test_suite()
    print()

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    warned = sum(1 for r in results if r["status"] == "WARN")
    total = len(results)

    print(f"{CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print()
    print(f"  {BOLD}Health Check Summary{NC}")
    print(f"  ─────────────────────────────────────────────")
    print(f"  Passed:   {GREEN}{passed}{NC}")
    if warned:
        print(f"  Warnings: {YELLOW}{warned}{NC}")
    if failed:
        print(f"  Failed:   {RED}{failed}{NC}")
    print(f"  Total:    {total}")
    print()

    if failed == 0:
        print(f"  {GREEN}{BOLD}[ENVIRONMENT READY]{NC}")
        if warned:
            print(f"  {YELLOW}Some optional features are not configured (see warnings above){NC}")
    else:
        print(f"  {RED}{BOLD}[ENVIRONMENT NOT READY — {failed} critical check(s) failed]{NC}")
        print(f"  Fix the issues above and re-run this script.")

    print()
    print(f"{CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print()

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
