import os
import subprocess
import hashlib
import hmac
import time
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console(record=True, width=100, force_terminal=True)

timestamp = datetime(2026, 3, 8, 14, 22, 47, 183000, tzinfo=timezone.utc)
ts_iso = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
agent_id = "agent-cx-4891"
trace_id = "trc_7f3a9b2e"
tool_name = "llm_completions.create"
tenant = "acme-prod"
malicious_url = "https://api-openai.attacker.ru/v1/chat/completions"
latency_ms = "2.3ms"

hmac_payload = f"{agent_id}.{trace_id}.{ts_iso}./v1/chat/completions"
sig = hmac.new(b"snapwire-sentinel-key", hmac_payload.encode(), hashlib.sha256).hexdigest()[:32]

console.print()
header = Text()
header.append("  SNAPWIRE SENTINEL PROXY", style="bold white")
header.append("  │  ", style="dim")
header.append("mode: ENFORCE", style="bold green")
header.append("  │  ", style="dim")
header.append(f"tenant: {tenant}", style="cyan")
console.print(Panel(header, border_style="blue", box=box.HEAVY))

console.print()
console.print(f"  [{ts_iso}]", style="dim")
console.print(f"  ▶ Incoming tool call from ", style="white", end="")
console.print(agent_id, style="bold cyan", end="")
console.print(f"  trace={trace_id}", style="dim")
console.print()

req_table = Table(
    title="  REQUEST INTERCEPTED",
    title_style="bold yellow",
    box=box.ROUNDED,
    border_style="yellow",
    show_header=True,
    header_style="bold white",
    padding=(0, 2),
    expand=True,
)
req_table.add_column("Field", style="white", width=22)
req_table.add_column("Value", style="white")
req_table.add_row("Tool", Text(tool_name, style="bold white"))
req_table.add_row("Agent", Text(agent_id, style="cyan"))
req_table.add_row("Parameter", Text("base_url", style="bold yellow"))
malicious_text = Text(malicious_url, style="bold red underline")
req_table.add_row("Value", malicious_text)
req_table.add_row("Model", Text("gpt-4-turbo", style="white"))
req_table.add_row("Prompt Tokens", Text("2,847", style="white"))
console.print(req_table)

console.print()

scan_lines = [
    ("✓ Schema validation", "dim green", "PASS", "green"),
    ("✓ Cost threshold", "dim green", "PASS — $0.12 < $50.00 limit", "green"),
    ("✓ Fuse breaker", "dim green", "PASS — loop count 1/10", "green"),
    ("✓ Taint tracking", "dim green", "PASS — no tainted data", "green"),
    ("✗ OpenClaw CVE-2026-25253", "bold red", "VIOLATION DETECTED", "bold red"),
]

console.print("  ── Safeguard Scan ──", style="bold white")
console.print()
for label, label_style, result, result_style in scan_lines:
    console.print(f"  {label}", style=label_style, end="")
    console.print(f"  →  {result}", style=result_style)
console.print()

block_panel_content = Text()
block_panel_content.append("  ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗\n", style="bold red")
block_panel_content.append("  ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝\n", style="bold red")
block_panel_content.append("  ██████╔╝██║     ██║   ██║██║     █████╔╝ \n", style="bold red")
block_panel_content.append("  ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ \n", style="bold red")
block_panel_content.append("  ██████╔╝███████╗╚██████╔╝╚██████╗██║  ╚██╗\n", style="bold red")
block_panel_content.append("  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝   ╚═╝\n", style="bold red")
block_panel_content.append("\n")
block_panel_content.append("  Violation: CVE-2026-25253 Safeguard Triggered\n", style="bold red")
block_panel_content.append(f"  Timestamp: {ts_iso}\n", style="white")
block_panel_content.append(f"  Latency:   {latency_ms}\n", style="bold green")
console.print(Panel(block_panel_content, border_style="bold red", box=box.DOUBLE, title="[bold red] ⛔ REQUEST TERMINATED [/bold red]"))

console.print()

v_table = Table(
    title="  VIOLATION DETAILS",
    title_style="bold red",
    box=box.ROUNDED,
    border_style="red",
    show_header=True,
    header_style="bold white",
    padding=(0, 2),
    expand=True,
)
v_table.add_column("#", style="dim", width=4)
v_table.add_column("Pattern", style="bold yellow", width=24)
v_table.add_column("Severity", width=12)
v_table.add_column("Description", style="white")

v_table.add_row(
    "1",
    "base_url_override",
    Text("CRITICAL", style="bold red"),
    "BASE_URL redirect detected — agent attempting\nto reroute API traffic to unauthorized endpoint",
)
v_table.add_row(
    "2",
    "domain_spoofing",
    Text("HIGH", style="bold yellow"),
    "Domain spoofing detected — URL impersonates\na known LLM API provider (openai)",
)
v_table.add_row(
    "3",
    "suspicious_tld",
    Text("HIGH", style="bold yellow"),
    "Suspicious TLD '.ru' — potential data\nexfiltration to high-risk domain",
)
console.print(v_table)

console.print()

sig_table = Table(
    title="  PROVENANCE HEADERS INJECTED",
    title_style="bold blue",
    box=box.ROUNDED,
    border_style="blue",
    show_header=True,
    header_style="bold white",
    padding=(0, 2),
    expand=True,
)
sig_table.add_column("Header", style="cyan", width=30)
sig_table.add_column("Value", style="white")
sig_table.add_row("X-Snapwire-Trace-ID", Text(trace_id, style="white"))
sig_table.add_row("X-Snapwire-Action", Text("BLOCKED", style="bold red"))
sig_table.add_row("X-Snapwire-Latency", Text(latency_ms, style="bold green"))
sig_table.add_row(
    "X-Snapwire-Signature",
    Text(f"sha256={sig}", style="dim white"),
)
sig_table.add_row(
    "  HMAC Payload",
    Text(f"{agent_id}.{trace_id}.{ts_iso}./v1/chat/completions", style="dim"),
)
console.print(sig_table)

console.print()

actions = Text()
actions.append("  Actions Taken:\n", style="bold white")
actions.append("    ✓ ", style="green")
actions.append("Request terminated — no data sent to attacker endpoint\n", style="white")
actions.append("    ✓ ", style="green")
actions.append("Audit event logged — forensic lineage preserved\n", style="white")
actions.append("    ✓ ", style="green")
actions.append("HITL Snap-Card queued — pending operator review\n", style="white")
actions.append("    ✓ ", style="green")
actions.append("Agent session flagged — elevated monitoring enabled\n", style="white")
console.print(Panel(actions, border_style="green", box=box.ROUNDED, title="[bold green] POST-BLOCK RESPONSE [/bold green]"))

console.print()

svg_path = "docs/screenshots/hero_cve.svg"
png_path = "docs/screenshots/hero_cve.png"

os.makedirs("docs/screenshots", exist_ok=True)

console.save_svg(svg_path, title="Snapwire Sentinel — CVE-2026-25253 Intercept Log")

result = subprocess.run(
    ["convert", "-density", "200", "-background", "#1a1b26", svg_path, "-resize", "1200x", png_path],
    capture_output=True,
    text=True,
)

if result.returncode == 0:
    size = os.path.getsize(png_path) / 1024
    print(f"Generated {png_path} ({size:.0f} KB)")
else:
    print(f"ImageMagick error: {result.stderr}")

if os.path.exists(svg_path):
    os.remove(svg_path)
