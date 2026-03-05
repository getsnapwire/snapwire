#!/usr/bin/env python3
import os
import sys


RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"


def color(text, c):
    if not sys.stdout.isatty():
        return text
    return f"{c}{text}{RESET}"


def check_required():
    results = []

    admin_email = os.environ.get("ADMIN_EMAIL", "").strip()
    if admin_email:
        results.append(("PASS", "ADMIN_EMAIL", f"Set to {admin_email}"))
    else:
        results.append(("FAIL", "ADMIN_EMAIL", "Missing — required for admin access and platform security"))

    db_url = os.environ.get("DATABASE_URL", "").strip()
    if db_url:
        if "sqlite" in db_url.lower():
            results.append(("WARN", "DATABASE_URL", "Using SQLite — not recommended for production"))
        else:
            results.append(("PASS", "DATABASE_URL", "PostgreSQL configured"))
    else:
        results.append(("WARN", "DATABASE_URL", "Not set — falling back to SQLite (snapwire.db)"))

    session_secret = os.environ.get("SESSION_SECRET", "").strip()
    if session_secret:
        results.append(("PASS", "SESSION_SECRET", "Set"))
    else:
        results.append(("WARN", "SESSION_SECRET", "Not set — auto-generated on each restart (sessions will not persist)"))

    return results


def check_recommended():
    results = []

    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    has_openai = bool(os.environ.get("OPENAI_API_KEY", "").strip())
    if has_anthropic and has_openai:
        results.append(("PASS", "LLM API Keys", "Both ANTHROPIC_API_KEY and OPENAI_API_KEY set"))
    elif has_anthropic:
        results.append(("PASS", "LLM API Keys", "ANTHROPIC_API_KEY set"))
    elif has_openai:
        results.append(("PASS", "LLM API Keys", "OPENAI_API_KEY set"))
    else:
        results.append(("WARN", "LLM API Keys", "Neither ANTHROPIC_API_KEY nor OPENAI_API_KEY set — AI features (rule evaluation, drift detection, tool grading) will be unavailable"))

    slack = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if slack:
        results.append(("PASS", "SLACK_WEBHOOK_URL", "Configured"))
    else:
        results.append(("INFO", "SLACK_WEBHOOK_URL", "Not set — Slack notifications disabled"))

    smtp = os.environ.get("SMTP_HOST", "").strip()
    if smtp:
        results.append(("PASS", "SMTP_HOST", f"Set to {smtp}"))
    else:
        results.append(("INFO", "SMTP_HOST", "Not set — email notifications disabled"))

    return results


def check_optional():
    results = []

    ts_site = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
    ts_secret = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
    if ts_site and ts_secret:
        results.append(("PASS", "Turnstile (CAPTCHA)", "Both keys configured"))
    elif ts_site or ts_secret:
        results.append(("WARN", "Turnstile (CAPTCHA)", "Only one key set — both TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY are needed"))
    else:
        results.append(("INFO", "Turnstile (CAPTCHA)", "Not configured — bot protection disabled"))

    sentinel_port = os.environ.get("SENTINEL_PORT", "").strip()
    sentinel_mode = os.environ.get("SENTINEL_MODE", "").strip()
    if sentinel_port or sentinel_mode:
        results.append(("PASS", "Sentinel", f"SENTINEL_PORT={sentinel_port or 'default'}, SENTINEL_MODE={sentinel_mode or 'default'}"))
    else:
        results.append(("INFO", "Sentinel", "Not configured — using defaults"))

    return results


def check_database():
    db_url = os.environ.get("DATABASE_URL", "").strip()
    if not db_url:
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "snapwire.db")
        db_url = f"sqlite:///{db_path}"

    try:
        if "sqlite" in db_url.lower():
            import sqlite3
            path = db_url.replace("sqlite:///", "")
            conn = sqlite3.connect(path, timeout=5)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            conn.close()
            return ("PASS", "Database Connectivity", f"SQLite connected — {len(tables)} tables found")
        else:
            try:
                import psycopg2
                conn = psycopg2.connect(db_url, connect_timeout=5)
                cursor = conn.cursor()
                cursor.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
                count = cursor.fetchone()[0]
                conn.close()
                return ("PASS", "Database Connectivity", f"PostgreSQL connected — {count} tables found")
            except ImportError:
                from sqlalchemy import create_engine, text
                engine = create_engine(db_url, connect_args={"connect_timeout": 5} if "postgresql" in db_url else {})
                with engine.connect() as conn:
                    result = conn.execute(text("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'"))
                    count = result.scalar()
                return ("PASS", "Database Connectivity", f"PostgreSQL connected — {count} tables found")
    except Exception as e:
        return ("FAIL", "Database Connectivity", f"Connection failed — {e}")


def print_results(title, results):
    print(f"\n{color(BOLD + title, CYAN)}")
    print("-" * 60)
    for status, name, detail in results:
        if status == "PASS":
            icon = color("  ✓ PASS", GREEN)
        elif status == "FAIL":
            icon = color("  ✗ FAIL", RED)
        elif status == "WARN":
            icon = color("  ⚠ WARN", YELLOW)
        else:
            icon = color("  ℹ INFO", CYAN)
        print(f"{icon}  {color(name, BOLD)}")
        print(f"         {detail}")


def main():
    print(color(f"\n{'='*60}", CYAN))
    print(color(" Snapwire Environment Validator", BOLD + CYAN))
    print(color(f"{'='*60}", CYAN))

    required = check_required()
    recommended = check_recommended()
    optional = check_optional()
    db_result = check_database()

    print_results("REQUIRED", required)
    print_results("RECOMMENDED", recommended)
    print_results("OPTIONAL", optional)
    print_results("DATABASE", [db_result])

    all_results = required + recommended + optional + [db_result]
    total = len(all_results)
    passed = sum(1 for r in all_results if r[0] == "PASS")
    failed = sum(1 for r in all_results if r[0] == "FAIL")
    warnings = sum(1 for r in all_results if r[0] == "WARN")

    print(f"\n{color('='*60, CYAN)}")
    if failed == 0:
        print(color(f" ✓ {passed}/{total} checks passed. Snapwire is ready.", GREEN + BOLD))
    else:
        print(color(f" ✗ {failed} issue(s) found, {warnings} warning(s). {passed}/{total} checks passed.", RED + BOLD))
    print(color(f"{'='*60}\n", CYAN))

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
