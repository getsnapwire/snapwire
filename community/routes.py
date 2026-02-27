import json
import re
from datetime import datetime
from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask_login import current_user
from app import db
from models import (
    CommunityProfile, UserBadge, CommunityRule, RuleRating,
    BADGE_DEFINITIONS, TIER_NAMES, AuditLogEntry,
)
from community.grader import grade_rule_code
from community.achievements import (
    get_or_create_profile, check_and_award_badges, get_leaderboard,
    get_wall_of_fame, get_user_badges, award_badge, recalculate_tier,
)
from src.tenant import get_current_tenant_id

community_bp = Blueprint('community', __name__)


def _require_auth():
    if not current_user.is_authenticated:
        return jsonify({"error": "Authentication required"}), 401
    return None


def _is_stealth_mode():
    try:
        from models import TenantSettings
        from src.tenant import get_current_tenant_id
        tenant_id = get_current_tenant_id()
        if tenant_id:
            settings = TenantSettings.query.filter_by(tenant_id=tenant_id).first()
        else:
            settings = TenantSettings.query.first()
        if settings and hasattr(settings, 'is_stealth_mode'):
            return settings.is_stealth_mode
    except Exception:
        pass
    return True


@community_bp.route("/api/sentinels.json", methods=["GET"])
def api_sentinels_json():
    if _is_stealth_mode():
        return jsonify({
            "version": 1,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_slots": 150,
            "claimed": 0,
            "sentinels": [],
            "stealth_mode": True,
        })
    sentinels = get_wall_of_fame()
    claimed = len(sentinels)
    sentinel_entries = []
    for idx, s in enumerate(sentinels, 1):
        sentinel_entries.append({
            "slot": idx,
            "display_name": s.get("display_name", "Anonymous"),
            "joined_at": s.get("joined_at", ""),
            "tier": s.get("tier_name", "Fuse Apprentice"),
        })
    return jsonify({
        "version": 1,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_slots": 150,
        "claimed": claimed,
        "sentinels": sentinel_entries,
    })


@community_bp.route("/api/sentinel/my-status", methods=["GET"])
def api_my_sentinel_status():
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    profile = get_or_create_profile(current_user)
    slot_number = None
    if profile.is_founding_sentinel:
        all_sentinels = CommunityProfile.query.filter_by(is_founding_sentinel=True).order_by(
            CommunityProfile.joined_at.asc()
        ).all()
        for idx, s in enumerate(all_sentinels, 1):
            if s.user_id == current_user.id:
                slot_number = idx
                break
    total_claimed = CommunityProfile.query.filter_by(is_founding_sentinel=True).count()
    return jsonify({
        "is_sentinel": profile.is_founding_sentinel,
        "slot_number": slot_number,
        "display_name": profile.display_name,
        "tier": profile.tier_name(),
        "total_claimed": total_claimed,
        "total_slots": 150,
        "slots_remaining": max(0, 150 - total_claimed),
    })


@community_bp.route("/leaderboard")
def leaderboard_page():
    if not current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if _is_stealth_mode() and getattr(current_user, 'role', '') != 'admin':
        from flask import flash
        flash("Community features are launching soon. Stay tuned!", "info")
        return redirect(url_for("dashboard"))
    return render_template("leaderboard.html", user=current_user)


@community_bp.route("/community-rules")
def community_rules_page():
    if not current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if _is_stealth_mode() and getattr(current_user, 'role', '') != 'admin':
        from flask import flash
        flash("Community features are launching soon. Stay tuned!", "info")
        return redirect(url_for("dashboard"))
    return render_template("community_rules.html", user=current_user)


@community_bp.route("/api/leaderboard", methods=["GET"])
def api_leaderboard():
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    limit = request.args.get("limit", 50, type=int)
    rankings = get_leaderboard(limit=min(limit, 100))
    return jsonify({"rankings": rankings})


@community_bp.route("/api/leaderboard/wall-of-fame", methods=["GET"])
def api_wall_of_fame():
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    sentinels = get_wall_of_fame()
    return jsonify({"sentinels": sentinels, "total_slots": 150})


@community_bp.route("/api/leaderboard/opt-in", methods=["POST"])
def api_opt_in():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    profile = get_or_create_profile(current_user)
    data = request.get_json(silent=True) or {}
    opted_in = data.get("opted_in", True)
    profile.opted_in = opted_in

    if data.get("display_name"):
        profile.display_name = data["display_name"][:100]

    db.session.commit()

    tenant_id = get_current_tenant_id()
    check_and_award_badges(current_user.id, tenant_id)

    return jsonify({"profile": profile.to_dict()})


@community_bp.route("/api/leaderboard/profile", methods=["GET"])
def api_my_profile():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    profile = get_or_create_profile(current_user)
    tenant_id = get_current_tenant_id()
    newly_awarded = check_and_award_badges(current_user.id, tenant_id)
    badges = get_user_badges(current_user.id)

    return jsonify({
        "profile": profile.to_dict(),
        "badges": badges,
        "newly_awarded": newly_awarded,
        "all_badges": BADGE_DEFINITIONS,
        "tier_names": TIER_NAMES,
    })


@community_bp.route("/api/community-rules", methods=["GET"])
def api_list_rules():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    category = request.args.get("category")
    verified_only = request.args.get("verified") == "true"
    sort = request.args.get("sort", "newest")

    query = CommunityRule.query
    if category:
        query = query.filter_by(category=category)
    if verified_only:
        query = query.filter_by(is_verified=True)

    if sort == "rating":
        query = query.order_by(CommunityRule.avg_rating.desc())
    elif sort == "imports":
        query = query.order_by(CommunityRule.import_count.desc())
    else:
        query = query.order_by(CommunityRule.submitted_at.desc())

    rules = query.limit(100).all()
    return jsonify({"rules": [r.to_dict() for r in rules]})


@community_bp.route("/api/community-rules/submit", methods=["POST"])
def api_submit_rule():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    category = (data.get("category") or "").strip()
    code = (data.get("code") or "").strip()

    if not name or not code:
        return jsonify({"error": "Name and code are required"}), 400

    if "def evaluate(" not in code:
        return jsonify({"error": "Rule must define an evaluate(tool_name, parameters) function"}), 400

    slug = re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')
    existing = CommunityRule.query.filter_by(slug=slug).first()
    if existing:
        return jsonify({"error": "A rule with this name already exists"}), 409

    test_results = grade_rule_code(code)
    is_verified = test_results["success"]

    rule = CommunityRule(
        author_id=current_user.id,
        name=name,
        slug=slug,
        description=description,
        category=category,
        code=code,
        is_verified=is_verified,
        scenarios_passed=test_results["passed"],
        scenarios_total=test_results["total"],
        test_results_json=json.dumps(test_results["results"]),
        avg_latency_ms=test_results.get("avg_latency_ms"),
        verified_at=datetime.utcnow() if is_verified else None,
    )
    db.session.add(rule)

    profile = get_or_create_profile(current_user)
    profile.rules_submitted = (profile.rules_submitted or 0) + 1
    if is_verified:
        profile.rules_verified = (profile.rules_verified or 0) + 1

    db.session.commit()

    tenant_id = get_current_tenant_id()
    check_and_award_badges(current_user.id, tenant_id)

    return jsonify({
        "rule": rule.to_dict(),
        "test_results": test_results,
        "is_verified": is_verified,
    })


@community_bp.route("/api/community-rules/<int:rule_id>/test", methods=["POST"])
def api_test_rule(rule_id):
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    rule = CommunityRule.query.get(rule_id)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    test_results = grade_rule_code(rule.code)
    rule.is_verified = test_results["success"]
    rule.scenarios_passed = test_results["passed"]
    rule.scenarios_total = test_results["total"]
    rule.test_results_json = json.dumps(test_results["results"])
    rule.avg_latency_ms = test_results.get("avg_latency_ms")
    if test_results["success"]:
        rule.verified_at = datetime.utcnow()
    db.session.commit()

    return jsonify({"test_results": test_results})


@community_bp.route("/api/community-rules/<int:rule_id>/rate", methods=["POST"])
def api_rate_rule(rule_id):
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    data = request.get_json(silent=True) or {}
    rating = data.get("rating")
    if not isinstance(rating, int) or rating < 1 or rating > 5:
        return jsonify({"error": "Rating must be 1-5"}), 400

    rule = CommunityRule.query.get(rule_id)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    if rule.author_id == current_user.id:
        return jsonify({"error": "Cannot rate your own rule"}), 400

    existing = RuleRating.query.filter_by(rule_id=rule_id, user_id=current_user.id).first()
    if existing:
        existing.rating = rating
    else:
        new_rating = RuleRating(rule_id=rule_id, user_id=current_user.id, rating=rating)
        db.session.add(new_rating)

    all_ratings = RuleRating.query.filter_by(rule_id=rule_id).all()
    if existing:
        total = sum(r.rating for r in all_ratings)
    else:
        total = sum(r.rating for r in all_ratings) + rating
    count = len(all_ratings) + (0 if existing else 1)
    rule.avg_rating = total / count if count > 0 else 0
    rule.rating_count = count

    profile = get_or_create_profile(current_user)
    profile.ratings_given = RuleRating.query.filter_by(user_id=current_user.id).count() + (0 if existing else 1)

    db.session.commit()

    tenant_id = get_current_tenant_id()
    check_and_award_badges(current_user.id, tenant_id)

    return jsonify({"avg_rating": round(rule.avg_rating, 1), "rating_count": rule.rating_count})


@community_bp.route("/api/community-rules/<int:rule_id>/import", methods=["POST"])
def api_import_rule(rule_id):
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    rule = CommunityRule.query.get(rule_id)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    rule.import_count = (rule.import_count or 0) + 1
    db.session.commit()

    return jsonify({"code": rule.code, "name": rule.name, "import_count": rule.import_count})


@community_bp.route("/api/community-rules/test-code", methods=["POST"])
def api_test_code():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    if not code:
        return jsonify({"error": "Code is required"}), 400

    test_results = grade_rule_code(code)
    return jsonify({"test_results": test_results})
