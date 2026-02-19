import json
import hashlib
import re
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta


_github_cache = {}
CACHE_TTL = 3600


def _fetch_github_repo_info(repo_url):
    match = re.search(r'github\.com/([^/]+)/([^/\s?.#]+)', repo_url)
    if not match:
        return None

    owner, repo = match.group(1), match.group(2).rstrip('.git')
    cache_key = f"{owner}/{repo}"

    if cache_key in _github_cache:
        cached_at, data = _github_cache[cache_key]
        if time.time() - cached_at < CACHE_TTL:
            return data

    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        req = urllib.request.Request(api_url, headers={
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AgenticFirewall/1.0'
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            result = {
                'owner': owner,
                'repo': repo,
                'stars': data.get('stargazers_count', 0),
                'forks': data.get('forks_count', 0),
                'open_issues': data.get('open_issues_count', 0),
                'created_at': data.get('created_at'),
                'updated_at': data.get('updated_at'),
                'pushed_at': data.get('pushed_at'),
                'language': data.get('language'),
                'license': data.get('license', {}).get('spdx_id') if data.get('license') else None,
                'archived': data.get('archived', False),
                'description': data.get('description', ''),
                'watchers': data.get('subscribers_count', 0),
            }
            _github_cache[cache_key] = (time.time(), result)
            return result
    except Exception:
        return None


def _score_github_reputation(info):
    if not info:
        return 0, []

    signals = []
    score = 50

    stars = info.get('stars', 0)
    if stars >= 1000:
        score += 20
        signals.append({'type': 'positive', 'label': f'{stars:,} stars', 'detail': 'Well-known project with significant community trust'})
    elif stars >= 100:
        score += 12
        signals.append({'type': 'positive', 'label': f'{stars:,} stars', 'detail': 'Moderately popular project'})
    elif stars >= 10:
        score += 5
        signals.append({'type': 'neutral', 'label': f'{stars} stars', 'detail': 'Small but established project'})
    else:
        score -= 10
        signals.append({'type': 'warning', 'label': f'{stars} stars', 'detail': 'Very few stars — limited community validation'})

    if info.get('created_at'):
        try:
            created = datetime.fromisoformat(info['created_at'].replace('Z', '+00:00'))
            age_days = (datetime.now(created.tzinfo) - created).days
            if age_days > 365:
                score += 10
                signals.append({'type': 'positive', 'label': f'{age_days // 365}+ years old', 'detail': 'Established project with history'})
            elif age_days > 90:
                score += 5
                signals.append({'type': 'neutral', 'label': f'{age_days} days old', 'detail': 'Relatively new project'})
            else:
                score -= 15
                signals.append({'type': 'warning', 'label': f'{age_days} days old', 'detail': 'Very new project — exercise caution'})
        except Exception:
            pass

    if info.get('pushed_at'):
        try:
            pushed = datetime.fromisoformat(info['pushed_at'].replace('Z', '+00:00'))
            days_since = (datetime.now(pushed.tzinfo) - pushed).days
            if days_since > 365:
                score -= 10
                signals.append({'type': 'warning', 'label': f'Last updated {days_since} days ago', 'detail': 'Project may be abandoned'})
            elif days_since < 30:
                score += 5
                signals.append({'type': 'positive', 'label': 'Recently updated', 'detail': f'Last push {days_since} days ago'})
        except Exception:
            pass

    if info.get('license'):
        score += 5
        signals.append({'type': 'positive', 'label': f'License: {info["license"]}', 'detail': 'Has an open-source license'})
    else:
        score -= 5
        signals.append({'type': 'warning', 'label': 'No license', 'detail': 'No license detected — usage rights unclear'})

    if info.get('archived'):
        score -= 20
        signals.append({'type': 'warning', 'label': 'Archived', 'detail': 'This repository is archived and no longer maintained'})

    return max(0, min(100, score)), signals


def _check_url_safety(url):
    signals = []
    score_modifier = 0

    if not url:
        return 0, []

    suspicious_patterns = [
        (r'bit\.ly|tinyurl|t\.co|goo\.gl', 'URL shortener detected', -15),
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Raw IP address in URL', -20),
        (r'(\.exe|\.bat|\.cmd|\.ps1|\.sh|\.vbs)(\?|$)', 'Executable file extension', -25),
        (r'\.ru/|\.cn/|\.tk/|\.ml/', 'High-risk TLD', -10),
        (r'https://', 'Uses HTTPS', 5),
    ]

    for pattern, label, modifier in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            signal_type = 'positive' if modifier > 0 else 'warning'
            signals.append({'type': signal_type, 'label': label, 'detail': f'Pattern detected in URL: {url[:80]}'})
            score_modifier += modifier

    if url.startswith('http://') and not re.search(r'localhost|127\.0\.0\.1', url):
        score_modifier -= 10
        signals.append({'type': 'warning', 'label': 'No HTTPS', 'detail': 'Connection is not encrypted'})

    return score_modifier, signals


def calculate_risk_score(tool_name, tool_params=None, source_url=None, tenant_id=None):
    signals = []
    base_score = 50

    if source_url and 'github.com' in source_url:
        github_info = _fetch_github_repo_info(source_url)
        gh_score, gh_signals = _score_github_reputation(github_info)
        base_score = gh_score
        signals.extend(gh_signals)

    if tool_params and isinstance(tool_params, dict):
        url_fields = ['url', 'endpoint', 'target', 'href', 'link', 'uri']
        for field in url_fields:
            if field in tool_params and isinstance(tool_params[field], str):
                url_mod, url_signals = _check_url_safety(tool_params[field])
                base_score += url_mod
                signals.extend(url_signals)

    high_risk_tools = ['execute_command', 'run_shell', 'delete_file', 'drop_table', 'send_email', 'transfer_funds', 'modify_permissions']
    if tool_name in high_risk_tools:
        base_score -= 15
        signals.append({'type': 'warning', 'label': 'High-risk tool category', 'detail': f'"{tool_name}" is classified as a high-risk operation'})

    read_only_tools = ['get_', 'list_', 'read_', 'fetch_', 'search_', 'query_']
    if any(tool_name.startswith(prefix) for prefix in read_only_tools):
        base_score += 10
        signals.append({'type': 'positive', 'label': 'Read-only operation', 'detail': 'This tool appears to be read-only'})

    final_score = max(0, min(100, base_score))

    return {
        'score': final_score,
        'grade': _score_to_grade(final_score),
        'signals': signals,
        'disclaimer': 'Intelligence Signals are probabilistic and for informational use only. Final action remains User responsibility.',
        'assessed_at': datetime.utcnow().isoformat(),
    }


def _score_to_grade(score):
    if score >= 80:
        return 'A'
    elif score >= 60:
        return 'B'
    elif score >= 40:
        return 'C'
    elif score >= 20:
        return 'D'
    return 'F'


def record_risk_signal(tenant_id, tool_name, score, grade, signals, source_url=None):
    from app import db
    from models import RiskSignal

    signal = RiskSignal(
        tenant_id=tenant_id,
        tool_name=tool_name,
        score=score,
        grade=grade,
        signals_json=json.dumps(signals),
        source_url=source_url,
    )
    db.session.add(signal)
    db.session.commit()
    return signal


def get_risk_signals(tenant_id, limit=50):
    from models import RiskSignal
    signals = RiskSignal.query.filter_by(tenant_id=tenant_id).order_by(RiskSignal.assessed_at.desc()).limit(limit).all()
    return [s.to_dict() for s in signals]


def get_tool_risk_summary(tenant_id):
    from models import RiskSignal
    from sqlalchemy import func
    from app import db

    latest = db.session.query(
        RiskSignal.tool_name,
        func.max(RiskSignal.assessed_at).label('latest')
    ).filter_by(tenant_id=tenant_id).group_by(RiskSignal.tool_name).subquery()

    results = db.session.query(RiskSignal).join(
        latest,
        (RiskSignal.tool_name == latest.c.tool_name) & (RiskSignal.assessed_at == latest.c.latest)
    ).filter(RiskSignal.tenant_id == tenant_id).all()

    return [r.to_dict() for r in results]
