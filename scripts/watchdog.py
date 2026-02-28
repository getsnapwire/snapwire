#!/usr/bin/env python3
"""
Snapwire Watchdog — Scheduled Batch Ingestor + Slack Failure Alerts

Runs the batch ingestor against a configurable source and sends Slack
notifications when tools fail the CVE gauntlet or receive D/F grades.

Usage:
    python scripts/watchdog.py
    WATCHDOG_SOURCE_URL=https://registry.example.com/tools.json python scripts/watchdog.py

Environment Variables:
    WATCHDOG_SOURCE_URL  — URL to fetch tool schemas from (optional)
    SLACK_WEBHOOK_URL    — Slack incoming webhook for failure alerts
"""

import json
import os
import sys
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("watchdog")

DEFAULT_LOCAL_FILE = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_logs.json")


def send_slack_alert(webhook_url, failures, summary):
    import urllib.request
    import urllib.error

    failure_lines = []
    for f in failures[:15]:
        tool = f.get("tool_name", "unknown")
        grade = f.get("grade", "?")
        cve_passed = f.get("cve_passed", 0)
        cve_failed = f.get("cve_failed", 0)
        reason = f.get("reason", "")
        failure_lines.append(f"- `{tool}` — Grade: {grade}, CVE: {cve_passed}/{cve_passed + cve_failed} passed — {reason}")

    failure_text = "\n".join(failure_lines)
    if len(failures) > 15:
        failure_text += f"\n_...and {len(failures) - 15} more_"

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "\U0001f6a8 Snapwire Watchdog Alert", "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total Processed:*\n{summary.get('total', 0)}"},
                    {"type": "mrkdwn", "text": f"*Failures Found:*\n{len(failures)}"},
                    {"type": "mrkdwn", "text": f"*Ingested:*\n{summary.get('ingested', 0)}"},
                    {"type": "mrkdwn", "text": f"*Pending Review:*\n{summary.get('pending_review', 0)}"},
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Failed Tools:*\n{failure_text}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Watchdog run at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"}
                ]
            }
        ]
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status == 200:
                logger.info("Slack alert sent successfully")
                return True
            else:
                logger.warning(f"Slack webhook returned status {resp.status}")
                return False
    except urllib.error.URLError as e:
        logger.error(f"Failed to send Slack alert: {e}")
        return False


def filter_failures(summary):
    failures = []
    for result in summary.get("results", []):
        reasons = []
        grade = result.get("grade", "U")
        cve_failed = result.get("cve_failed", 0)

        if cve_failed > 0:
            reasons.append(f"CVE gauntlet: {cve_failed} pattern(s) missed")
        if grade in ("D", "F"):
            reasons.append(f"Safety grade: {grade}")

        if reasons:
            failures.append({
                "tool_name": result.get("tool_name", "unknown"),
                "grade": grade,
                "cve_passed": result.get("cve_passed", 0),
                "cve_failed": cve_failed,
                "status": result.get("status", "unknown"),
                "reason": "; ".join(reasons),
            })
    return failures


def run_watchdog(source_url=None, source_file=None):
    from scripts.batch_ingestor import load_tools_from_url, load_tools_from_file, process_tools, print_summary

    tools = None

    if source_url:
        logger.info(f"Fetching tools from URL: {source_url}")
        tools = load_tools_from_url(source_url)
        if tools is None:
            logger.error("Failed to load tools from URL")
            return {"error": "Failed to load tools from URL", "failures": [], "summary": None}
    elif source_file and os.path.exists(source_file):
        logger.info(f"Loading tools from file: {source_file}")
        try:
            tools = load_tools_from_file(source_file)
        except Exception as e:
            logger.error(f"Failed to load tools from file: {e}")
            return {"error": str(e), "failures": [], "summary": None}
    else:
        logger.warning("No source configured and no default file found. Nothing to process.")
        return {"error": "No source configured", "failures": [], "summary": None}

    if not tools:
        logger.warning("No tools found in source")
        return {"error": "No tools found", "failures": [], "summary": None}

    logger.info(f"Processing {len(tools)} tools...")

    try:
        from app import app
        with app.app_context():
            summary = process_tools(tools, dry_run=False, no_heal=False, no_chaos=True)
    except ImportError:
        logger.warning("Flask app not available — running in dry-run mode")
        summary = process_tools(tools, dry_run=True, no_heal=False, no_chaos=True)

    print_summary(summary)

    failures = filter_failures(summary)

    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if failures and webhook_url:
        logger.info(f"Found {len(failures)} failure(s) — sending Slack alert")
        send_slack_alert(webhook_url, failures, summary)
    elif failures:
        logger.warning(f"Found {len(failures)} failure(s) but SLACK_WEBHOOK_URL not configured — skipping alert")
    else:
        logger.info("All tools passed — no alert needed (silent success)")

    return {
        "failures": failures,
        "summary": {
            "total": summary.get("total", 0),
            "ingested": summary.get("ingested", 0),
            "healed": summary.get("healed", 0),
            "failed": summary.get("failed", 0),
            "pending_review": summary.get("pending_review", 0),
            "failure_count": len(failures),
        },
        "ran_at": datetime.utcnow().isoformat(),
    }


def main():
    source_url = os.environ.get("WATCHDOG_SOURCE_URL", "").strip() or None
    source_file = None

    if not source_url:
        default_path = os.path.abspath(DEFAULT_LOCAL_FILE)
        if os.path.exists(default_path):
            source_file = default_path
        else:
            logger.info("No WATCHDOG_SOURCE_URL set and no default local file found")

    result = run_watchdog(source_url=source_url, source_file=source_file)

    if result.get("error"):
        logger.error(f"Watchdog finished with error: {result['error']}")
        sys.exit(1)

    failure_count = len(result.get("failures", []))
    if failure_count > 0:
        logger.info(f"Watchdog complete: {failure_count} failure(s) detected")
    else:
        logger.info("Watchdog complete: all clear")


if __name__ == "__main__":
    main()
