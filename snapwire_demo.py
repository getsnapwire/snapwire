#!/usr/bin/env python3
"""
Snapwire Demo — Simulate a malicious AI agent to see your Kill Feed light up.

Runs 22 attack scenarios against your local Snapwire instance, covering:
  - Credential exfiltration (AWS keys, SSH keys, .env files)
  - Environment access (env vars, shadow files, cloud tokens)
  - PII leakage (SSNs, credit cards, contact info)
  - Crypto transactions (ETH transfers, token swaps, seed phrases)
  - Domain exfiltration (rogue domains, pastebin, DNS tunnels)
  - Safe calls (benign operations that should be allowed)

Usage:
    python snapwire_demo.py
    python snapwire_demo.py --api-key af_your_key
    python snapwire_demo.py --url http://localhost:5000 --category credential_exfil
    python snapwire_demo.py --delay 1.0 --category pii_leakage

Open your dashboard to watch the Kill Feed update in real time!
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tests.scenarios.attack_scenarios import SCENARIOS, get_categories

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

CATEGORY_COLORS = {
    "credential_exfil": RED,
    "env_access": YELLOW,
    "pii_leakage": "\033[95m",
    "crypto_transaction": "\033[93m",
    "domain_exfil": "\033[91m",
    "safe_calls": GREEN,
}

CATEGORY_ICONS = {
    "credential_exfil": "🔑",
    "env_access": "🔧",
    "pii_leakage": "👤",
    "crypto_transaction": "💰",
    "domain_exfil": "🌐",
    "safe_calls": "✅",
}


def check_health(url):
    try:
        req = urllib.request.Request(f"{url}/health")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("status") == "healthy"
    except Exception:
        return False


def run_intercept(url, api_key, scenario):
    payload = {
        "tool_name": scenario["tool_name"],
        "parameters": scenario["parameters"],
        "agent_id": f"demo-{scenario['category']}",
        "intent": scenario["description"],
        "context": f"Snapwire Demo — Scenario {scenario['id']}: {scenario['name']}",
    }

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"{url}/api/intercept", data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode("utf-8"))
        except Exception:
            data = {"status": "error", "message": str(e)}
        return data, e.code
    except Exception as e:
        return {"status": "error", "message": str(e)}, 0


def print_banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════╗
║          ⚡ SNAPWIRE ATTACK SIMULATOR ⚡              ║
║                                                      ║
║  Simulating a malicious AI agent against your        ║
║  Snapwire instance. Watch the Kill Feed light up!    ║
╚══════════════════════════════════════════════════════╝{RESET}
""")


def print_scenario_result(idx, total, scenario, response, status_code):
    cat = scenario["category"]
    color = CATEGORY_COLORS.get(cat, "")
    icon = CATEGORY_ICONS.get(cat, "❓")

    status = response.get("status", "error")
    was_blocked = status_code in (403, 429) or "blocked" in status.lower()
    expected_block = scenario["should_block"]
    correct = was_blocked == expected_block

    status_display = f"{RED}BLOCKED{RESET}" if was_blocked else f"{GREEN}ALLOWED{RESET}"
    check = f"{GREEN}✓{RESET}" if correct else f"{RED}✗ MISMATCH{RESET}"

    print(f"  {DIM}[{idx}/{total}]{RESET} {icon} {color}{BOLD}{scenario['name']}{RESET}")
    print(f"        {DIM}Tool:{RESET} {scenario['tool_name']}  {DIM}Category:{RESET} {color}{cat}{RESET}")
    print(f"        {DIM}Result:{RESET} {status_display}  {DIM}Expected:{RESET} {'BLOCK' if expected_block else 'ALLOW'}  {check}")

    risk_score = response.get("audit", {}).get("risk_score")
    if risk_score is not None:
        risk_color = RED if risk_score >= 70 else YELLOW if risk_score >= 40 else GREEN
        print(f"        {DIM}Risk:{RESET} {risk_color}{risk_score}/100{RESET}")

    violations = response.get("audit", {}).get("violations", [])
    if violations:
        for v in violations[:2]:
            print(f"        {DIM}→ [{v.get('severity', '?')}] {v.get('reason', '')[:80]}{RESET}")

    print()
    return correct


def main():
    parser = argparse.ArgumentParser(description="Snapwire Attack Simulator")
    parser.add_argument("--url", default=os.environ.get("SNAPWIRE_URL", "http://localhost:5000"),
                        help="Snapwire instance URL (default: http://localhost:5000)")
    parser.add_argument("--api-key", default=os.environ.get("SNAPWIRE_API_KEY", ""),
                        help="Snapwire API key")
    parser.add_argument("--category", choices=get_categories() + ["all"], default="all",
                        help="Run only scenarios from this category")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay between scenarios in seconds (default: 0.5)")
    args = parser.parse_args()

    print_banner()

    print(f"  {DIM}Target:{RESET}   {args.url}")
    print(f"  {DIM}API Key:{RESET}  {'***' + args.api_key[-8:] if len(args.api_key) > 8 else '(not set)'}")

    print(f"\n  {DIM}Checking connectivity...{RESET}", end=" ")
    if not check_health(args.url):
        print(f"{RED}FAILED{RESET}")
        print(f"\n  {RED}Cannot connect to Snapwire at {args.url}{RESET}")
        print(f"  Make sure the server is running: {CYAN}python main.py{RESET}")
        sys.exit(1)
    print(f"{GREEN}OK{RESET}\n")

    scenarios = SCENARIOS
    if args.category != "all":
        scenarios = [s for s in SCENARIOS if s["category"] == args.category]

    if not scenarios:
        print(f"  {YELLOW}No scenarios found for category: {args.category}{RESET}")
        sys.exit(1)

    total = len(scenarios)
    correct = 0
    blocked = 0
    allowed = 0
    errors = 0

    categories_seen = {}
    current_cat = None

    for idx, scenario in enumerate(scenarios, 1):
        cat = scenario["category"]
        if cat != current_cat:
            current_cat = cat
            color = CATEGORY_COLORS.get(cat, "")
            icon = CATEGORY_ICONS.get(cat, "")
            print(f"  {color}{BOLD}━━━ {icon} {cat.upper().replace('_', ' ')} ━━━{RESET}\n")

        response, status_code = run_intercept(args.url, args.api_key, scenario)

        if status_code == 0:
            print(f"  {DIM}[{idx}/{total}]{RESET} {RED}ERROR: {response.get('message', 'Connection failed')}{RESET}\n")
            errors += 1
        else:
            was_correct = print_scenario_result(idx, total, scenario, response, status_code)
            if was_correct:
                correct += 1

            was_blocked = status_code in (403, 429) or "blocked" in response.get("status", "").lower()
            if was_blocked:
                blocked += 1
            else:
                allowed += 1

            categories_seen[cat] = categories_seen.get(cat, 0) + 1

        if idx < total:
            time.sleep(args.delay)

    accuracy = round((correct / total) * 100) if total > 0 else 0
    acc_color = GREEN if accuracy >= 80 else YELLOW if accuracy >= 60 else RED

    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════╗
║                    RESULTS                           ║
╚══════════════════════════════════════════════════════╝{RESET}

  {BOLD}Scenarios:{RESET}  {total} total
  {BOLD}Blocked:{RESET}    {RED}{blocked}{RESET}
  {BOLD}Allowed:{RESET}    {GREEN}{allowed}{RESET}
  {BOLD}Errors:{RESET}     {YELLOW}{errors}{RESET}
  {BOLD}Accuracy:{RESET}   {acc_color}{accuracy}%{RESET} ({correct}/{total} matched expected)

  {DIM}Categories covered: {', '.join(categories_seen.keys())}{RESET}
""")

    if blocked > 0:
        print(f"  {CYAN}{BOLD}Open your Snapwire dashboard to see the Kill Feed! 🛡️{RESET}")
        print(f"  {DIM}{args.url}/dashboard{RESET}\n")


if __name__ == "__main__":
    main()
