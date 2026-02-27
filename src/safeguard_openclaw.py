import re
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

ALLOWED_HOSTS = frozenset({
    "api.openai.com",
    "api.anthropic.com",
    "localhost",
    "127.0.0.1",
})

ALLOWED_HOST_SUFFIXES = (
    ".openai.azure.com",
)

URL_KEYWORD_PATTERN = re.compile(
    r"(?i)(base[_\-]?url|api[_\-]?base|endpoint|api[_\-]?endpoint|OPENAI_BASE_URL|ANTHROPIC_BASE_URL|OPENAI_API_BASE|AZURE_OPENAI_ENDPOINT)"
)

CREDENTIAL_KEYWORD_PATTERN = re.compile(
    r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token|bearer|authorization|password|credential)"
)

URL_EXTRACT_PATTERN = re.compile(r"https?://[^\s\"',\)]+")

SPOOFING_PATTERNS = [
    re.compile(r"(?i)https?://(api[\.\-]openai[^\.a-z]|openai[^\.a-z]|api[\.\-]anthropic[^\.a-z]|anthropic[^\.a-z]|claude[\.\-]api|gpt[\.\-]api|api[\.\-]claude|openai[\.\-]proxy)"),
]

SUSPICIOUS_TLDS = frozenset({
    "ru", "cn", "tk", "ml", "ga", "cf", "pw", "cc", "xyz", "top", "buzz", "icu",
})

URL_PARAM_KEYS = frozenset({
    "url", "endpoint", "host", "server", "target", "destination", "callback", "webhook", "redirect",
})


def _is_host_allowed(url_str: str) -> bool:
    try:
        parsed = urlparse(url_str)
        host = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return False

    if not host:
        return False

    if host in ALLOWED_HOSTS:
        return True

    if host.startswith("127.") or host == "::1":
        return True

    for suffix in ALLOWED_HOST_SUFFIXES:
        if host.endswith(suffix):
            return True

    return False


def _extract_urls(text: str) -> List[str]:
    return URL_EXTRACT_PATTERN.findall(text)


def _check_domain_spoofing(url_str: str) -> Optional[dict]:
    for pattern in SPOOFING_PATTERNS:
        match = pattern.search(url_str)
        if match:
            return {
                "pattern": "domain_spoofing",
                "severity": "high",
                "description": "Domain spoofing detected — URL impersonates a known LLM API provider",
                "cve": "CVE-2026-25253",
                "matched": match.group(0)[:200],
            }

    try:
        parsed = urlparse(url_str)
        host = (parsed.hostname or "").lower()
        for trusted in ("openai.com", "anthropic.com"):
            if trusted in host and host != f"api.{trusted}" and not host.endswith(f".{trusted}"):
                return {
                    "pattern": "domain_spoofing",
                    "severity": "critical",
                    "description": f"Domain spoofing detected — host contains '{trusted}' but is not the legitimate API endpoint",
                    "cve": "CVE-2026-25253",
                    "matched": url_str[:200],
                }
    except Exception:
        pass

    return None


def _check_suspicious_tld(url_str: str) -> Optional[dict]:
    try:
        parsed = urlparse(url_str)
        host = (parsed.hostname or "").lower()
        parts = host.split(".")
        if parts and parts[-1] in SUSPICIOUS_TLDS:
            return {
                "pattern": "suspicious_tld",
                "severity": "high",
                "description": f"Suspicious TLD '.{parts[-1]}' in URL — potential data exfiltration to high-risk domain",
                "cve": "CVE-2026-25253",
                "matched": url_str[:200],
            }
    except Exception:
        pass
    return None


def _flatten_params(params: Any, prefix: str = "") -> List[tuple]:
    pairs = []
    if isinstance(params, dict):
        for k, v in params.items():
            key_path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, str):
                pairs.append((key_path, v))
            elif isinstance(v, (dict, list)):
                pairs.extend(_flatten_params(v, key_path))
    elif isinstance(params, list):
        for i, item in enumerate(params):
            pairs.extend(_flatten_params(item, f"{prefix}[{i}]"))
    elif isinstance(params, str):
        pairs.append((prefix, params))
    return pairs


def check_openclaw(
    tool_name: str,
    parameters: Dict[str, Any],
    agent_id: str = "unknown",
    tenant_id: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    violations = []
    flat_pairs = _flatten_params(parameters)
    all_text = f"tool_name={tool_name} " + " ".join(f"{k}={v}" for k, v in flat_pairs)

    for key, value in flat_pairs:
        key_lower = key.rsplit(".", 1)[-1].lower() if "." in key else key.lower()
        urls_in_value = _extract_urls(value)

        if URL_KEYWORD_PATTERN.search(key):
            for url in urls_in_value:
                if not _is_host_allowed(url):
                    violations.append({
                        "pattern": "base_url_override",
                        "severity": "critical",
                        "description": "BASE_URL redirect detected — agent attempting to reroute API traffic to unauthorized endpoint",
                        "cve": "CVE-2026-25253",
                        "matched": f"{key}={url}"[:200],
                    })

        if CREDENTIAL_KEYWORD_PATTERN.search(key):
            for url in urls_in_value:
                if not _is_host_allowed(url):
                    violations.append({
                        "pattern": "credential_exfiltration",
                        "severity": "critical",
                        "description": "Credential exfiltration attempt — API key paired with unauthorized URL redirect",
                        "cve": "CVE-2026-25253",
                        "matched": f"{key}=...{url}"[:200],
                    })

        if key_lower in URL_PARAM_KEYS:
            for url in urls_in_value:
                tld_result = _check_suspicious_tld(url)
                if tld_result:
                    violations.append(tld_result)

    for url in _extract_urls(all_text):
        spoof = _check_domain_spoofing(url)
        if spoof and not any(v["pattern"] == "domain_spoofing" and v["matched"] == spoof["matched"] for v in violations):
            violations.append(spoof)

    env_match = re.search(
        r"(?i)(OPENAI_BASE_URL|ANTHROPIC_BASE_URL|OPENAI_API_BASE|AZURE_OPENAI_ENDPOINT)\s*=\s*(https?://\S+)",
        all_text,
    )
    if env_match:
        env_url = env_match.group(2)
        if not _is_host_allowed(env_url):
            violations.append({
                "pattern": "env_var_injection",
                "severity": "critical",
                "description": "Environment variable injection — agent attempting to override LLM provider URL via env var",
                "cve": "CVE-2026-25253",
                "matched": env_match.group(0)[:200],
            })

    config_match = re.search(
        r"(?i)(config|settings|options)\s*[\[\{].*?(base[_\-]?url|api[_\-]?base|endpoint)\s*[:=]\s*(https?://\S+)",
        all_text,
    )
    if config_match:
        config_url = config_match.group(3)
        if not _is_host_allowed(config_url):
            violations.append({
                "pattern": "config_override",
                "severity": "high",
                "description": "Configuration object override — agent embedding URL redirect in config/settings payload",
                "cve": "CVE-2026-25253",
                "matched": config_match.group(0)[:200],
            })

    if not violations:
        return None

    max_severity = "critical" if any(v["severity"] == "critical" for v in violations) else "high"

    result = {
        "blocked": True,
        "safeguard": "openclaw",
        "severity": max_severity,
        "violations": violations,
        "message": f"OpenClaw safeguard triggered: {violations[0]['description']}",
        "tool_name": tool_name,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "timestamp": datetime.utcnow().isoformat(),
    }

    logger.warning(
        f"OPENCLAW BLOCK | agent={agent_id} | tool={tool_name} | "
        f"patterns={[v['pattern'] for v in violations]} | severity={max_severity}"
    )

    return result


def get_openclaw_stats(tenant_id: Optional[int] = None) -> Dict[str, Any]:
    return {
        "safeguard": "openclaw",
        "patterns_active": 6,
        "cve_coverage": ["CVE-2026-25253"],
        "categories": [
            "base_url_override",
            "credential_exfiltration",
            "domain_spoofing",
            "env_var_injection",
            "suspicious_tld",
            "config_override",
        ],
    }
