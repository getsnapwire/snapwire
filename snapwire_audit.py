#!/usr/bin/env python3
"""
Snapwire Audit CLI — Scan your agent logs for recursive loops.

Usage:
    python snapwire_audit.py --file agent_logs.json
    python snapwire_audit.py --file agent_logs.json --cost 0.03
    python snapwire_audit.py --file agent_logs.json --window 30 --threshold 3

Input format (JSON array of tool-call records):
    [
        {
            "timestamp": "2026-02-21T10:00:01Z",
            "tool_name": "web_search",
            "parameters": {"query": "latest news"},
            "agent_id": "my-agent"
        },
        ...
    ]

Each record needs at minimum: timestamp, tool_name, parameters.
The agent_id field is optional (defaults to "unknown").
"""

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta


GITHUB_URL = "https://github.com/snapwire-ai/snapwire"


def parse_timestamp(ts_str):
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


def detect_loops(records, window_seconds=30, threshold=3):
    by_agent = defaultdict(list)
    for rec in records:
        ts = parse_timestamp(str(rec.get("timestamp", "")))
        if ts is None:
            continue
        agent_id = rec.get("agent_id", "unknown")
        tool = rec.get("tool_name", rec.get("tool", "unknown"))
        params = rec.get("parameters", rec.get("params", {}))
        fp = fingerprint(tool, params)
        by_agent[agent_id].append({
            "timestamp": ts,
            "tool_name": tool,
            "fingerprint": fp,
            "parameters": params,
        })

    for agent_id in by_agent:
        by_agent[agent_id].sort(key=lambda x: x["timestamp"])

    loops = []
    for agent_id, calls in by_agent.items():
        seen_loops = set()
        for i, call in enumerate(calls):
            window_start = call["timestamp"] - timedelta(seconds=window_seconds)
            matches = [
                c for c in calls
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
                    })

    return loops, sum(len(c) for c in by_agent.values())


def format_report(loops, total_calls, cost_per_call, file_path):
    border = "=" * 60
    print()
    print(border)
    print("  SNAPWIRE AUDIT REPORT")
    print(border)
    print(f"  File:           {file_path}")
    print(f"  Total calls:    {total_calls}")
    print(f"  Loops found:    {len(loops)}")
    print(border)

    if not loops:
        print()
        print("  No recursive loops detected.")
        print("  Your agents look clean.")
        print()
        print(border)
        print(f"  Add the Snapwire badge to signal safe agents:")
        print(f"  ![Protected by Snapwire]({GITHUB_URL}/raw/main/static/badge-snapwire.svg)")
        print(border)
        print()
        return 0.0

    total_wasted_calls = 0
    print()
    for i, loop in enumerate(loops, 1):
        excess = loop["repeat_count"] - 1
        total_wasted_calls += excess
        cost = excess * cost_per_call
        print(f"  LOOP #{i}")
        print(f"    Agent:      {loop['agent_id']}")
        print(f"    Tool:       {loop['tool_name']}")
        print(f"    Repeats:    {loop['repeat_count']}x in {loop['window_seconds']}s")
        print(f"    Wasted:     {excess} redundant call(s)")
        print(f"    Est. cost:  ${cost:.2f}")
        print(f"    Window:     {loop['first_seen']} -> {loop['last_seen']}")
        print()

    total_savings = total_wasted_calls * cost_per_call
    print(border)
    print(f"  TOTAL WASTED CALLS:    {total_wasted_calls}")
    print(f"  ESTIMATED BURN:        ${total_savings:.2f}")
    print(border)
    print()
    print(f"  Snapwire would have snapped these loops automatically.")
    print(f"  Fork the repo to protect your next session:")
    print(f"  {GITHUB_URL}")
    print()
    print(f"  Badge for your README:")
    print(f"  ![Protected by Snapwire]({GITHUB_URL}/raw/main/static/badge-snapwire.svg)")
    print(border)
    print()
    return total_savings


def main():
    parser = argparse.ArgumentParser(
        description="Snapwire Audit — Scan agent logs for recursive loops and estimate wasted spend.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python snapwire_audit.py --file logs.json --cost 0.03\n"
    )
    parser.add_argument("--file", "-f", required=True, help="Path to JSON log file")
    parser.add_argument("--cost", "-c", type=float, default=0.01,
                        help="Estimated cost per tool call in USD (default: $0.01)")
    parser.add_argument("--window", "-w", type=int, default=30,
                        help="Loop detection window in seconds (default: 30)")
    parser.add_argument("--threshold", "-t", type=int, default=3,
                        help="Minimum repeat count to flag a loop (default: 3)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON instead of formatted text")

    args = parser.parse_args()

    try:
        with open(args.file, "r") as f:
            records = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.file}: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(records, list):
        print("Error: Log file must contain a JSON array of tool-call records.", file=sys.stderr)
        sys.exit(1)

    loops, total_calls = detect_loops(records, args.window, args.threshold)

    if args.json:
        output = {
            "file": args.file,
            "total_calls": total_calls,
            "loops_detected": len(loops),
            "loops": [
                {
                    **loop,
                    "first_seen": loop["first_seen"].isoformat(),
                    "last_seen": loop["last_seen"].isoformat(),
                    "estimated_waste_usd": (loop["repeat_count"] - 1) * args.cost,
                }
                for loop in loops
            ],
            "total_estimated_waste_usd": sum((l["repeat_count"] - 1) * args.cost for l in loops),
            "snapwire_url": GITHUB_URL,
        }
        print(json.dumps(output, indent=2))
    else:
        format_report(loops, total_calls, args.cost, args.file)

    sys.exit(1 if loops else 0)


if __name__ == "__main__":
    main()
