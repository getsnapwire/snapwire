#!/usr/bin/env python3
"""
Snapwire Audit CLI — Scan your agent logs for security threats and waste.

Usage:
    python snapwire_audit.py --file agent_logs.json
    python snapwire_audit.py --file agent_logs.jsonl
    python snapwire_audit.py --file agent_logs.json --cost 0.03
    python snapwire_audit.py --file agent_logs.json --json
    python snapwire_audit.py --file agent_logs.json --verbose

Supported log formats:
    - JSON array of tool-call records
    - JSONL (one JSON object per line)
    - Nested formats (LangChain, CrewAI, AutoGPT style)

Each record needs at minimum: tool_name (or tool/function_call), parameters (or args/arguments).
Timestamps and agent_id are optional but improve detection quality.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta


GITHUB_URL = "https://github.com/snapwire-ai/snapwire"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}

CREDENTIAL_PATTERNS = [
    (".env", SEVERITY_CRITICAL, "Environment file access"),
    ("ENV[", SEVERITY_CRITICAL, "Environment variable access"),
    ("os.environ", SEVERITY_CRITICAL, "Python environment access"),
    ("process.env", SEVERITY_CRITICAL, "Node.js environment access"),
    ("SECRET_KEY", SEVERITY_CRITICAL, "Secret key access"),
    ("API_KEY", SEVERITY_CRITICAL, "API key access"),
    ("DATABASE_URL", SEVERITY_HIGH, "Database credential access"),
    ("AWS_SECRET", SEVERITY_CRITICAL, "AWS secret access"),
    ("AWS_ACCESS_KEY", SEVERITY_CRITICAL, "AWS access key"),
    ("PRIVATE_KEY", SEVERITY_CRITICAL, "Private key access"),
    ("ANTHROPIC_API_KEY", SEVERITY_CRITICAL, "Anthropic API key access"),
    ("OPENAI_API_KEY", SEVERITY_CRITICAL, "OpenAI API key access"),
    ("STRIPE_SECRET", SEVERITY_CRITICAL, "Stripe secret access"),
    ("/etc/shadow", SEVERITY_CRITICAL, "System password file"),
    ("/etc/passwd", SEVERITY_HIGH, "System user file"),
    ("~/.ssh/", SEVERITY_CRITICAL, "SSH key directory"),
    ("~/.aws/credentials", SEVERITY_CRITICAL, "AWS credentials file"),
    ("~/.config/gcloud", SEVERITY_HIGH, "GCloud config access"),
    (".pem", SEVERITY_HIGH, "PEM certificate access"),
    (".key", SEVERITY_HIGH, "Key file access"),
    ("id_rsa", SEVERITY_CRITICAL, "RSA private key"),
    ("id_ed25519", SEVERITY_CRITICAL, "ED25519 private key"),
]

EXFIL_PATTERNS = [
    (r"https?://[^\s]+\.(ru|cn|tk|xyz|top|pw|cc)/", SEVERITY_HIGH, "Suspicious domain in URL"),
    (r"curl\s+.*-d\s+", SEVERITY_MEDIUM, "curl POST data exfiltration"),
    (r"wget\s+.*--post-data", SEVERITY_MEDIUM, "wget POST data exfiltration"),
    (r"base64", SEVERITY_LOW, "Base64 encoding (potential data obfuscation)"),
    (r"\\x[0-9a-fA-F]{2}", SEVERITY_MEDIUM, "Hex-encoded data (potential obfuscation)"),
]

VELOCITY_WINDOW = 5
VELOCITY_THRESHOLD = 10


def parse_timestamp(ts_str):
    if ts_str is None:
        return None
    ts_str = str(ts_str)
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromtimestamp(float(ts_str))
    except (ValueError, TypeError, OSError):
        pass
    return None


def fingerprint(tool_name, parameters):
    params_str = json.dumps(parameters, sort_keys=True, default=str)
    params_hash = hashlib.md5(params_str.encode()).hexdigest()
    return f"{tool_name}:{params_hash}"


def flatten_values(obj):
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(flatten_values(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(flatten_values(v) for v in obj)
    return str(obj)


def normalize_record(raw):
    fc = raw.get("function_call")
    fc_name = fc.get("name") if isinstance(fc, dict) else None
    fc_args = fc.get("arguments") if isinstance(fc, dict) else None

    tool_name = (
        raw.get("tool_name")
        or raw.get("tool")
        or fc_name
        or raw.get("name")
        or "unknown"
    )

    parameters = (
        raw.get("parameters")
        or raw.get("params")
        or raw.get("args")
        or raw.get("arguments")
        or raw.get("input")
        or fc_args
        or {}
    )

    if isinstance(parameters, str):
        try:
            parameters = json.loads(parameters)
        except (json.JSONDecodeError, TypeError):
            parameters = {"raw": parameters}

    timestamp = (
        raw.get("timestamp")
        or raw.get("ts")
        or raw.get("time")
        or raw.get("created_at")
        or raw.get("datetime")
    )

    agent_id = (
        raw.get("agent_id")
        or raw.get("agent")
        or raw.get("run_id")
        or raw.get("session_id")
        or "unknown"
    )

    return {
        "tool_name": tool_name,
        "parameters": parameters,
        "timestamp": timestamp,
        "agent_id": agent_id,
    }


def extract_records_from_nested(data, records=None):
    if records is None:
        records = []

    if isinstance(data, dict):
        if any(k in data for k in ("tool_name", "tool", "function_call", "name")):
            records.append(data)
        for key in ("steps", "actions", "tool_calls", "calls", "events", "messages", "runs", "logs", "history"):
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    extract_records_from_nested(item, records)
        if "run" in data and isinstance(data["run"], dict):
            extract_records_from_nested(data["run"], records)
        if "data" in data and isinstance(data["data"], (list, dict)):
            extract_records_from_nested(data["data"], records)
    elif isinstance(data, list):
        for item in data:
            extract_records_from_nested(item, records)

    return records


def load_log_file(file_path):
    with open(file_path, "r") as f:
        content = f.read().strip()

    if not content:
        return [], "empty"

    if content.startswith("[") or content.startswith("{"):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                if all(isinstance(r, dict) for r in data):
                    has_tool = any(
                        any(k in r for k in ("tool_name", "tool", "function_call", "name"))
                        for r in data
                    )
                    if has_tool:
                        return [normalize_record(r) for r in data], "json_array"
                    else:
                        extracted = extract_records_from_nested(data)
                        return [normalize_record(r) for r in extracted], "json_nested"
                return [], "json_unknown"
            elif isinstance(data, dict):
                extracted = extract_records_from_nested(data)
                if extracted:
                    return [normalize_record(r) for r in extracted], "json_nested"
                if any(k in data for k in ("tool_name", "tool", "function_call")):
                    return [normalize_record(data)], "json_single"
                return [], "json_unknown"
        except json.JSONDecodeError:
            pass

    records = []
    for line in content.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                extracted = extract_records_from_nested(obj)
                if extracted:
                    records.extend([normalize_record(r) for r in extracted])
                elif any(k in obj for k in ("tool_name", "tool", "function_call", "name")):
                    records.append(normalize_record(obj))
        except json.JSONDecodeError:
            continue

    if records:
        return records, "jsonl"

    return [], "unknown"


def detect_loops(records, window_seconds=30, threshold=3):
    by_agent = defaultdict(list)
    for rec in records:
        ts = parse_timestamp(rec.get("timestamp"))
        agent_id = rec.get("agent_id", "unknown")
        tool = rec.get("tool_name", "unknown")
        params = rec.get("parameters", {})
        fp = fingerprint(tool, params)
        by_agent[agent_id].append({
            "timestamp": ts,
            "tool_name": tool,
            "fingerprint": fp,
            "parameters": params,
        })

    for agent_id in by_agent:
        by_agent[agent_id].sort(key=lambda x: x["timestamp"] or datetime.min)

    loops = []
    for agent_id, calls in by_agent.items():
        timed_calls = [c for c in calls if c["timestamp"] is not None]
        if not timed_calls:
            fps = defaultdict(int)
            for c in calls:
                fps[c["fingerprint"]] += 1
            for fp_key, count in fps.items():
                if count >= threshold:
                    matching = [c for c in calls if c["fingerprint"] == fp_key]
                    loops.append({
                        "agent_id": agent_id,
                        "tool_name": matching[0]["tool_name"],
                        "repeat_count": count,
                        "window_seconds": None,
                        "first_seen": None,
                        "last_seen": None,
                        "fingerprint": fp_key,
                        "severity": SEVERITY_HIGH,
                    })
            continue

        seen_loops = set()
        for i, call in enumerate(timed_calls):
            window_start = call["timestamp"] - timedelta(seconds=window_seconds)
            matches = [
                c for c in timed_calls
                if c["fingerprint"] == call["fingerprint"]
                and window_start <= c["timestamp"] <= call["timestamp"]
            ]
            if len(matches) >= threshold:
                loop_key = (agent_id, call["fingerprint"],
                            matches[0]["timestamp"].isoformat())
                if loop_key not in seen_loops:
                    seen_loops.add(loop_key)
                    loops.append({
                        "agent_id": agent_id,
                        "tool_name": call["tool_name"],
                        "repeat_count": len(matches),
                        "window_seconds": window_seconds,
                        "first_seen": matches[0]["timestamp"],
                        "last_seen": matches[-1]["timestamp"],
                        "fingerprint": call["fingerprint"],
                        "severity": SEVERITY_HIGH if len(matches) >= 5 else SEVERITY_MEDIUM,
                    })

    return loops, sum(len(c) for c in by_agent.values())


def detect_credential_access(records):
    findings = []
    seen = set()
    for i, rec in enumerate(records):
        tool = rec.get("tool_name", "")
        params = rec.get("parameters", {})
        search_str = (tool + " " + flatten_values(params)).lower()

        for pattern, severity, description in CREDENTIAL_PATTERNS:
            if pattern.lower() in search_str:
                key = (i, pattern)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "type": "credential_access",
                        "severity": severity,
                        "description": description,
                        "pattern": pattern,
                        "tool_name": tool,
                        "record_index": i,
                        "agent_id": rec.get("agent_id", "unknown"),
                    })
    return findings


def detect_exfiltration(records):
    findings = []
    for i, rec in enumerate(records):
        tool = rec.get("tool_name", "")
        params = rec.get("parameters", {})
        search_str = tool + " " + flatten_values(params)

        for pattern, severity, description in EXFIL_PATTERNS:
            if re.search(pattern, search_str, re.IGNORECASE):
                findings.append({
                    "type": "exfiltration",
                    "severity": severity,
                    "description": description,
                    "pattern": pattern,
                    "tool_name": tool,
                    "record_index": i,
                    "agent_id": rec.get("agent_id", "unknown"),
                })
    return findings


def detect_velocity_spikes(records):
    findings = []
    timed = []
    for rec in records:
        ts = parse_timestamp(rec.get("timestamp"))
        if ts:
            timed.append((ts, rec))

    timed.sort(key=lambda x: x[0])

    for i, (ts, rec) in enumerate(timed):
        window_end = ts + timedelta(seconds=VELOCITY_WINDOW)
        in_window = [t for t in timed if ts <= t[0] <= window_end]
        if len(in_window) >= VELOCITY_THRESHOLD:
            findings.append({
                "type": "velocity_spike",
                "severity": SEVERITY_MEDIUM,
                "description": f"{len(in_window)} calls in {VELOCITY_WINDOW}s window",
                "calls_in_window": len(in_window),
                "window_start": ts,
                "window_end": window_end,
                "agent_id": rec.get("agent_id", "unknown"),
            })
            break

    return findings


def format_severity(severity):
    icons = {
        SEVERITY_CRITICAL: "[!!]",
        SEVERITY_HIGH: "[!]",
        SEVERITY_MEDIUM: "[~]",
        SEVERITY_LOW: "[.]",
        SEVERITY_INFO: "[i]",
    }
    return f"{icons.get(severity, '[?]')} {severity}"


def format_report(loops, cred_findings, exfil_findings, velocity_findings,
                  total_calls, cost_per_call, file_path, log_format, verbose=False):
    border = "=" * 62
    thin = "-" * 62
    print()
    print(border)
    print("  SNAPWIRE AUDIT REPORT")
    print(border)
    print(f"  File:           {file_path}")
    print(f"  Format:         {log_format}")
    print(f"  Total calls:    {total_calls}")
    print(thin)

    all_findings = []
    for loop in loops:
        all_findings.append(("Loop Detection", loop["severity"], loop))
    for f in cred_findings:
        all_findings.append(("Credential Access", f["severity"], f))
    for f in exfil_findings:
        all_findings.append(("Data Exfiltration", f["severity"], f))
    for f in velocity_findings:
        all_findings.append(("Velocity Spike", f["severity"], f))

    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x[1], 99))

    severity_counts = defaultdict(int)
    for _, sev, _ in all_findings:
        severity_counts[sev] += 1

    print(f"  Findings:       {len(all_findings)}")
    if severity_counts:
        parts = []
        for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]:
            if severity_counts[sev]:
                parts.append(f"{severity_counts[sev]} {sev}")
        if parts:
            print(f"  Breakdown:      {', '.join(parts)}")
    print(border)

    if not all_findings:
        print()
        print("  No issues detected. Your agents look clean.")
        print()
        _print_badge()
        return 0.0

    total_wasted_calls = 0

    if loops:
        print()
        print(f"  HALLUCINATION LOOPS ({len(loops)} found)")
        print(thin)
        for i, loop in enumerate(loops, 1):
            excess = loop["repeat_count"] - 1
            total_wasted_calls += excess
            cost = excess * cost_per_call
            print(f"  {format_severity(loop['severity'])} Loop #{i}")
            print(f"    Agent:      {loop['agent_id']}")
            print(f"    Tool:       {loop['tool_name']}")
            print(f"    Repeats:    {loop['repeat_count']}x", end="")
            if loop["window_seconds"]:
                print(f" in {loop['window_seconds']}s")
            else:
                print(" (no timestamps)")
            print(f"    Wasted:     {excess} redundant call(s)")
            print(f"    Est. cost:  ${cost:.2f}")
            if loop["first_seen"] and loop["last_seen"]:
                print(f"    Window:     {loop['first_seen']} -> {loop['last_seen']}")
            if verbose:
                print(f"    Fingerprint: {loop['fingerprint']}")
            print()

    if cred_findings:
        print(f"  CREDENTIAL ACCESS ATTEMPTS ({len(cred_findings)} found)")
        print(thin)
        for i, f in enumerate(cred_findings, 1):
            print(f"  {format_severity(f['severity'])} #{i}: {f['description']}")
            print(f"    Tool:       {f['tool_name']}")
            print(f"    Pattern:    {f['pattern']}")
            print(f"    Agent:      {f['agent_id']}")
            if verbose:
                print(f"    Record:     #{f['record_index']}")
            print()

    if exfil_findings:
        print(f"  DATA EXFILTRATION SIGNALS ({len(exfil_findings)} found)")
        print(thin)
        for i, f in enumerate(exfil_findings, 1):
            print(f"  {format_severity(f['severity'])} #{i}: {f['description']}")
            print(f"    Tool:       {f['tool_name']}")
            print(f"    Agent:      {f['agent_id']}")
            if verbose:
                print(f"    Pattern:    {f['pattern']}")
                print(f"    Record:     #{f['record_index']}")
            print()

    if velocity_findings:
        print(f"  VELOCITY SPIKES ({len(velocity_findings)} found)")
        print(thin)
        for f in velocity_findings:
            print(f"  {format_severity(f['severity'])} {f['description']}")
            print(f"    Agent:      {f['agent_id']}")
            if verbose and f.get("window_start"):
                print(f"    Window:     {f['window_start']} -> {f['window_end']}")
            print()

    total_savings = total_wasted_calls * cost_per_call
    print(border)
    print(f"  SUMMARY")
    print(thin)
    print(f"  Total findings:        {len(all_findings)}")
    if loops:
        print(f"  Wasted calls:          {total_wasted_calls}")
        print(f"  Estimated burn:        ${total_savings:.2f}")
    if cred_findings:
        print(f"  Credential attempts:   {len(cred_findings)}")
    if exfil_findings:
        print(f"  Exfil signals:         {len(exfil_findings)}")
    if velocity_findings:
        print(f"  Velocity spikes:       {len(velocity_findings)}")
    print(border)
    print()
    print("  Snapwire catches these issues in real time.")
    print(f"  Fork and deploy your own fuse: {GITHUB_URL}")
    print()
    _print_badge()
    print()
    print("  DISCLAIMER: All findings are heuristic and advisory.")
    print("  The final Duty of Care remains with the human operator.")
    print()
    return total_savings


def _print_badge():
    border = "=" * 62
    print(border)
    print("  ADD THE BADGE TO YOUR README")
    print(border)
    print()
    print("  Show the world your agents are governed.")
    print("  Copy this into your README.md:")
    print()
    print(f"  [![Protected by Snapwire]({GITHUB_URL}/raw/main/static/badge-snapwire.svg)]({GITHUB_URL})")
    print()


def build_json_output(loops, cred_findings, exfil_findings, velocity_findings,
                      total_calls, cost_per_call, file_path, log_format):
    all_findings = []

    for loop in loops:
        all_findings.append({
            "type": "hallucination_loop",
            "severity": loop["severity"],
            "agent_id": loop["agent_id"],
            "tool_name": loop["tool_name"],
            "repeat_count": loop["repeat_count"],
            "window_seconds": loop["window_seconds"],
            "first_seen": loop["first_seen"].isoformat() if loop["first_seen"] else None,
            "last_seen": loop["last_seen"].isoformat() if loop["last_seen"] else None,
            "estimated_waste_usd": (loop["repeat_count"] - 1) * cost_per_call,
        })

    for f in cred_findings:
        all_findings.append({
            "type": "credential_access",
            "severity": f["severity"],
            "description": f["description"],
            "pattern": f["pattern"],
            "tool_name": f["tool_name"],
            "agent_id": f["agent_id"],
            "record_index": f["record_index"],
        })

    for f in exfil_findings:
        all_findings.append({
            "type": "data_exfiltration",
            "severity": f["severity"],
            "description": f["description"],
            "tool_name": f["tool_name"],
            "agent_id": f["agent_id"],
            "record_index": f["record_index"],
        })

    for f in velocity_findings:
        all_findings.append({
            "type": "velocity_spike",
            "severity": f["severity"],
            "description": f["description"],
            "calls_in_window": f["calls_in_window"],
            "agent_id": f["agent_id"],
            "window_start": f["window_start"].isoformat() if f.get("window_start") else None,
        })

    total_wasted = sum(l["repeat_count"] - 1 for l in loops)

    return {
        "file": file_path,
        "format": log_format,
        "total_calls": total_calls,
        "findings_count": len(all_findings),
        "severity_summary": {
            "critical": sum(1 for f in all_findings if f["severity"] == SEVERITY_CRITICAL),
            "high": sum(1 for f in all_findings if f["severity"] == SEVERITY_HIGH),
            "medium": sum(1 for f in all_findings if f["severity"] == SEVERITY_MEDIUM),
            "low": sum(1 for f in all_findings if f["severity"] == SEVERITY_LOW),
        },
        "loops_detected": len(loops),
        "credential_attempts": len(cred_findings),
        "exfil_signals": len(exfil_findings),
        "velocity_spikes": len(velocity_findings),
        "total_wasted_calls": total_wasted,
        "total_estimated_waste_usd": total_wasted * cost_per_call,
        "findings": all_findings,
        "snapwire_url": GITHUB_URL,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Snapwire Audit — Scan agent logs for loops, credential leaks, and anomalies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Supported formats:\n"
            "  JSON array    [{ tool_name, parameters, ... }, ...]\n"
            "  JSONL         One JSON object per line\n"
            "  Nested        LangChain/CrewAI/AutoGPT style with steps/actions/tool_calls\n"
            "\n"
            "Examples:\n"
            "  python snapwire_audit.py --file logs.json\n"
            "  python snapwire_audit.py --file logs.jsonl --cost 0.03 --verbose\n"
            "  python snapwire_audit.py --file logs.json --json | jq '.findings[]'\n"
        )
    )
    parser.add_argument("--file", "-f", required=True, help="Path to agent log file (JSON, JSONL, or nested)")
    parser.add_argument("--cost", "-c", type=float, default=0.01,
                        help="Estimated cost per tool call in USD (default: $0.01)")
    parser.add_argument("--window", "-w", type=int, default=30,
                        help="Loop detection window in seconds (default: 30)")
    parser.add_argument("--threshold", "-t", type=int, default=3,
                        help="Minimum repeat count to flag a loop (default: 3)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON (for CI/CD pipelines)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed findings with fingerprints and record indices")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(2)

    try:
        records, log_format = load_log_file(args.file)
    except json.JSONDecodeError as e:
        print(f"Error: Could not parse {args.file}: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading {args.file}: {e}", file=sys.stderr)
        sys.exit(2)

    if not records:
        if args.json:
            print(json.dumps({"file": args.file, "error": "No tool-call records found", "format": log_format}))
        else:
            print(f"\nNo tool-call records found in {args.file} (detected format: {log_format})")
            print("Make sure your logs contain objects with 'tool_name' or 'tool' fields.")
        sys.exit(2)

    loops, total_calls = detect_loops(records, args.window, args.threshold)
    cred_findings = detect_credential_access(records)
    exfil_findings = detect_exfiltration(records)
    velocity_findings = detect_velocity_spikes(records)

    has_issues = bool(loops or cred_findings or exfil_findings or velocity_findings)
    has_critical = any(
        f.get("severity") == SEVERITY_CRITICAL
        for f in cred_findings + exfil_findings
    ) or any(l.get("severity") == SEVERITY_CRITICAL for l in loops)

    if args.json:
        output = build_json_output(
            loops, cred_findings, exfil_findings, velocity_findings,
            total_calls, args.cost, args.file, log_format
        )
        output["exit_code"] = 2 if has_critical else (1 if has_issues else 0)
        print(json.dumps(output, indent=2, default=str))
    else:
        format_report(
            loops, cred_findings, exfil_findings, velocity_findings,
            total_calls, args.cost, args.file, log_format, verbose=args.verbose
        )

    if has_critical:
        sys.exit(2)
    elif has_issues:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
