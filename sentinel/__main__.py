"""
Snapwire Sentinel — Entry Point

Usage:
    python -m sentinel                  Start the proxy
    python -m sentinel --export-nist    Generate NIST compliance mapping
"""

import argparse
import asyncio
import logging
import os
import signal
import sys

BANNER = r"""
  ____                  _   _            _
 / ___|  ___ _ __  __ _| |_(_)_ __   ___| |
 \___ \ / _ \ '_ \/ _` | __| | '_ \ / _ \ |
  ___) |  __/ | | | (_| | |_| | | | |  __/ |
 |____/ \___|_| |_|\__,_|\__|_|_| |_|\___|_|

 Snapwire Sentinel Proxy — The 60-Second Agent Firewall
 ─────────────────────────────────────────────────────────
"""


def get_config() -> dict:
    return {
        "port": int(os.environ.get("SENTINEL_PORT", "8080")),
        "upstream_url": os.environ.get("UPSTREAM_URL", "https://api.openai.com"),
        "snapwire_url": os.environ.get("SNAPWIRE_URL", "http://localhost:5000"),
        "api_key": os.environ.get("SNAPWIRE_API_KEY", ""),
        "mode": os.environ.get("SENTINEL_MODE", "audit"),
        "agent_id": os.environ.get("SENTINEL_AGENT_ID", "sentinel-proxy"),
        "origin_id": os.environ.get("SENTINEL_ORIGIN_ID", "human-principal"),
        "signing_secret": os.environ.get("SNAPWIRE_SIGNING_SECRET", ""),
        "authorized_by": os.environ.get("SENTINEL_AUTHORIZED_BY", ""),
    }


def print_banner(config: dict):
    mode_labels = {
        "observe": "OBSERVE (Silent-Audit — zero traffic modification)",
        "audit": "AUDIT (Log + trace headers, always pass through)",
        "enforce": "ENFORCE (Block disallowed calls, fail-closed)",
    }
    mode_display = mode_labels.get(config["mode"], config["mode"])

    print(BANNER)
    print(f"  Mode:       {mode_display}")
    print(f"  Port:       {config['port']}")
    print(f"  Upstream:   {config['upstream_url']}")
    print(f"  Snapwire:   {config['snapwire_url']}")
    print(f"  Agent ID:   {config['agent_id']}")
    print(f"  Origin ID:  {config['origin_id']}")
    authorized_by = config.get("authorized_by") or config["origin_id"]
    print(f"  Auth'd By:  {authorized_by}")
    print(f"  Signature:  {'HMAC-SHA256 active' if config.get('signing_secret') else 'disabled (set SNAPWIRE_SIGNING_SECRET)'}")
    print()
    print("  Quick Start:")
    print(f"    OPENAI_BASE_URL=http://localhost:{config['port']}/v1 python my_agent.py")
    print()
    print("  ─────────────────────────────────────────────────────────")
    if config["mode"] == "enforce":
        print("  ⚠ ENFORCE mode: Snapwire unreachable → requests BLOCKED (fail-closed)")
    elif config["mode"] == "observe":
        print("  Silent-Audit: zero latency impact, non-blocking logging")
    print()


async def run_proxy(config: dict):
    from sentinel.proxy import SentinelProxy

    proxy = SentinelProxy(config)
    runner = await proxy.start()

    stop_event = asyncio.Event()

    def handle_signal():
        logging.getLogger("sentinel").info("Shutting down Sentinel Proxy...")
        stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_signal)
        except NotImplementedError:
            pass

    await stop_event.wait()
    await runner.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="Snapwire Sentinel — Transparent Reverse Proxy for AI Agent Governance"
    )
    parser.add_argument(
        "--export-nist",
        action="store_true",
        help="Generate NIST compliance mapping markdown file",
    )
    args = parser.parse_args()

    if args.export_nist:
        from sentinel.nist_export import export_nist_report
        config = get_config()
        export_nist_report(config)
        return

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    config = get_config()

    if config["mode"] not in ("observe", "audit", "enforce"):
        print(f"Error: Invalid SENTINEL_MODE '{config['mode']}'. Use: observe, audit, enforce")
        sys.exit(1)

    print_banner(config)
    asyncio.run(run_proxy(config))


if __name__ == "__main__":
    main()
