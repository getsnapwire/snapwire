"""
Snapwire Demo Seed Script
Populates the database with realistic multi-agent chain data
for demonstrating the Forensic Lineage Map.

Usage:
    python seed_demo.py

The script is idempotent — it skips if demo data already exists.
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timedelta

os.environ.setdefault("FLASK_DEBUG", "0")

from app import app, db
from models import AuditLogEntry


def _hash(entry):
    parts = [
        entry.tool_name or "",
        entry.tool_params or "",
        entry.intent or "",
        entry.status or "",
        str(entry.risk_score or 0),
        entry.agent_id or "",
        entry.tenant_id or "",
        entry.created_at.isoformat() if entry.created_at else "",
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


DEMO_PREFIX = "demo-"

DEMO_ENTRIES = [
    {
        "agent_id": "demo-orchestrator",
        "parent_agent_id": None,
        "tool_name": "plan_task",
        "parameters": {"task": "Build and deploy user dashboard", "subtasks": 3},
        "intent": "Break down the project into subtasks and delegate to specialist agents",
        "status": "allowed",
        "risk_score": 5,
        "violations": [],
        "analysis": "Planning action within policy bounds. No sensitive operations.",
        "minutes_ago": 120,
    },
    {
        "agent_id": "demo-code-writer",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "write_file",
        "parameters": {"path": "src/components/Dashboard.tsx", "content": "..."},
        "intent": "Create the main dashboard component with user stats",
        "status": "allowed",
        "risk_score": 12,
        "violations": [],
        "analysis": "File write to source directory. Safe operation.",
        "minutes_ago": 110,
    },
    {
        "agent_id": "demo-code-writer",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "write_file",
        "parameters": {"path": "src/api/users.ts", "content": "..."},
        "intent": "Create API route for fetching user data",
        "status": "allowed",
        "risk_score": 15,
        "violations": [],
        "analysis": "File write to API directory. Standard development operation.",
        "minutes_ago": 105,
    },
    {
        "agent_id": "demo-code-writer",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "execute_shell",
        "parameters": {"command": "npm install chart.js"},
        "intent": "Install charting library for dashboard graphs",
        "status": "allowed",
        "risk_score": 25,
        "violations": [],
        "analysis": "Package installation via npm. Known safe package.",
        "minutes_ago": 100,
    },
    {
        "agent_id": "demo-code-writer",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "delete_database",
        "parameters": {"database": "production_users", "confirm": True},
        "intent": "Clear stale test data from production database",
        "status": "reasoning-requested",
        "risk_score": 95,
        "violations": [
            {"rule": "no_destructive_ops", "severity": "critical", "reason": "Deleting production database requires explicit justification."},
            {"rule": "data_protection", "severity": "high", "reason": "Operation affects production data store."},
        ],
        "analysis": "CRITICAL: Agent attempting to delete production database without reasoning. Reasoning enforcement triggered.",
        "minutes_ago": 95,
    },
    {
        "agent_id": "demo-code-writer",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "delete_database",
        "parameters": {"database": "production_users", "confirm": True},
        "intent": "Clear stale test data from production database",
        "status": "blocked",
        "risk_score": 95,
        "violations": [
            {"rule": "no_destructive_ops", "severity": "critical", "reason": "Deleting production database is not permitted."},
        ],
        "analysis": "Agent re-submitted with reasoning but intent does not match action scope. Blocked by constitutional rule.",
        "minutes_ago": 94,
    },
    {
        "agent_id": "demo-reviewer",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "read_file",
        "parameters": {"path": "src/components/Dashboard.tsx"},
        "intent": "Review the dashboard component code for quality and security issues",
        "status": "allowed",
        "risk_score": 3,
        "violations": [],
        "analysis": "Read-only file access. No risk.",
        "minutes_ago": 85,
    },
    {
        "agent_id": "demo-reviewer",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "run_tests",
        "parameters": {"suite": "unit", "coverage": True},
        "intent": "Run unit test suite with coverage reporting",
        "status": "allowed",
        "risk_score": 8,
        "violations": [],
        "analysis": "Test execution in sandboxed environment. Safe operation.",
        "minutes_ago": 80,
    },
    {
        "agent_id": "demo-reviewer",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "run_tests",
        "parameters": {"suite": "integration", "coverage": True},
        "intent": "Run integration test suite to validate API endpoints",
        "status": "allowed",
        "risk_score": 10,
        "violations": [],
        "analysis": "Integration test execution. No external access detected.",
        "minutes_ago": 75,
    },
    {
        "agent_id": "demo-deploy-agent",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "deploy_to_production",
        "parameters": {"environment": "prod", "version": "2.1.0", "strategy": "rolling"},
        "intent": "Deploy the reviewed dashboard to production with rolling update",
        "status": "blocked",
        "risk_score": 82,
        "violations": [
            {"rule": "require_approval_for_deploys", "severity": "high", "reason": "Production deployments require manual approval."},
        ],
        "analysis": "Production deployment blocked. Requires human approval before proceeding.",
        "minutes_ago": 60,
    },
    {
        "agent_id": "demo-deploy-agent",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "send_notification",
        "parameters": {"channel": "#deployments", "message": "Dashboard v2.1.0 ready for review"},
        "intent": "Notify the team that the deployment is ready for approval",
        "status": "allowed",
        "risk_score": 5,
        "violations": [],
        "analysis": "Notification to internal channel. Safe operation.",
        "minutes_ago": 55,
    },
    {
        "agent_id": "demo-deploy-agent",
        "parent_agent_id": "demo-orchestrator",
        "tool_name": "send_email",
        "parameters": {"to": "external@competitor.com", "subject": "Source code", "body": "..."},
        "intent": "Share deployment status with external partner",
        "status": "blocked",
        "risk_score": 88,
        "violations": [
            {"rule": "no_external_emails", "severity": "critical", "reason": "Sending email to external address violates data exfiltration rules."},
        ],
        "analysis": "BLOCKED: Agent attempted to email source code to external address. Deception detected — stated intent does not match email content.",
        "minutes_ago": 50,
    },
    {
        "agent_id": "demo-monitor",
        "parent_agent_id": "demo-deploy-agent",
        "tool_name": "check_metrics",
        "parameters": {"service": "dashboard-api", "metric": "error_rate"},
        "intent": "Monitor error rate after staging deployment",
        "status": "allowed",
        "risk_score": 2,
        "violations": [],
        "analysis": "Read-only metrics check. No risk.",
        "minutes_ago": 45,
    },
    {
        "agent_id": "demo-monitor",
        "parent_agent_id": "demo-deploy-agent",
        "tool_name": "check_metrics",
        "parameters": {"service": "dashboard-api", "metric": "latency_p99"},
        "intent": "Check P99 latency after staging deployment",
        "status": "allowed",
        "risk_score": 2,
        "violations": [],
        "analysis": "Read-only metrics check. No risk.",
        "minutes_ago": 40,
    },
]


def seed_demo():
    with app.app_context():
        existing = AuditLogEntry.query.filter(
            AuditLogEntry.agent_id.like(f"{DEMO_PREFIX}%")
        ).first()

        if existing:
            print("Demo data already exists. Skipping seed.")
            print("To re-seed, delete existing demo entries first:")
            print("  DELETE FROM audit_log WHERE agent_id LIKE 'demo-%';")
            return

        now = datetime.utcnow()
        created = 0

        for entry_data in DEMO_ENTRIES:
            entry = AuditLogEntry(
                tenant_id=None,
                tool_name=entry_data["tool_name"],
                tool_params=json.dumps(entry_data["parameters"]),
                intent=entry_data["intent"],
                status=entry_data["status"],
                risk_score=entry_data["risk_score"],
                violations_json=json.dumps(entry_data["violations"]),
                analysis=entry_data["analysis"],
                agent_id=entry_data["agent_id"],
                parent_agent_id=entry_data["parent_agent_id"],
                created_at=now - timedelta(minutes=entry_data["minutes_ago"]),
            )
            entry.content_hash = _hash(entry)
            db.session.add(entry)
            created += 1

        db.session.commit()

        print(f"\nSnapwire Demo Data Seeded Successfully")
        print(f"{'=' * 40}")
        print(f"  Entries created: {created}")
        print(f"  Agent chain: Human -> orchestrator -> [code-writer, reviewer, deploy-agent -> monitor]")
        print(f"  Statuses: allowed, blocked, reasoning-requested")
        print(f"\nOpen your dashboard to see the Forensic Lineage Map in action.")


if __name__ == "__main__":
    seed_demo()
