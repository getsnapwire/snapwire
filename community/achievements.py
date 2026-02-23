from datetime import datetime
from app import db
from models import (
    CommunityProfile, UserBadge, CommunityRule, RuleRating,
    LoopDetectorEvent, BADGE_DEFINITIONS,
    TIER_FUSE_APPRENTICE, TIER_CIRCUIT_BREAKER, TIER_GRID_OPERATOR, TIER_SENTINEL_PRIME,
)


FOUNDING_SENTINEL_LIMIT = 150


def get_or_create_profile(user):
    profile = CommunityProfile.query.filter_by(user_id=user.id).first()
    if not profile:
        display = user.display_name or user.email or user.id
        profile = CommunityProfile(user_id=user.id, display_name=display)
        db.session.add(profile)
        founding_count = CommunityProfile.query.filter_by(is_founding_sentinel=True).count()
        if founding_count < FOUNDING_SENTINEL_LIMIT:
            profile.is_founding_sentinel = True
        db.session.commit()
    return profile


def has_badge(user_id, badge_key):
    return UserBadge.query.filter_by(user_id=user_id, badge_key=badge_key).first() is not None


def award_badge(user_id, badge_key):
    if has_badge(user_id, badge_key):
        return False
    badge = UserBadge(user_id=user_id, badge_key=badge_key)
    db.session.add(badge)
    badge_info = next((b for b in BADGE_DEFINITIONS if b["key"] == badge_key), None)
    if badge_info:
        profile = CommunityProfile.query.filter_by(user_id=user_id).first()
        if profile:
            profile.total_points = (profile.total_points or 0) + badge_info["points"]
    db.session.commit()
    return True


def check_and_award_badges(user_id, tenant_id=None):
    awarded = []

    award_badge(user_id, "fork_deploy")
    if has_badge(user_id, "fork_deploy"):
        awarded.append("fork_deploy")

    if tenant_id:
        loop_count = LoopDetectorEvent.query.filter_by(tenant_id=tenant_id).count()
        if loop_count >= 1 and not has_badge(user_id, "first_loop_blocked"):
            award_badge(user_id, "first_loop_blocked")
            awarded.append("first_loop_blocked")

        total_savings = db.session.query(
            db.func.coalesce(db.func.sum(LoopDetectorEvent.estimated_savings), 0)
        ).filter_by(tenant_id=tenant_id).scalar() or 0

        profile = CommunityProfile.query.filter_by(user_id=user_id).first()
        if profile:
            profile.total_savings = total_savings
            db.session.commit()

        if total_savings >= 100 and not has_badge(user_id, "savings_100"):
            award_badge(user_id, "savings_100")
            awarded.append("savings_100")
        if total_savings >= 1000 and not has_badge(user_id, "savings_1000"):
            award_badge(user_id, "savings_1000")
            awarded.append("savings_1000")
        if total_savings >= 10000 and not has_badge(user_id, "savings_10000"):
            award_badge(user_id, "savings_10000")
            awarded.append("savings_10000")

    verified_rules = CommunityRule.query.filter_by(author_id=user_id, is_verified=True).count()
    if verified_rules >= 1 and not has_badge(user_id, "rule_author_1"):
        award_badge(user_id, "rule_author_1")
        awarded.append("rule_author_1")
    if verified_rules >= 3 and not has_badge(user_id, "rule_author_3"):
        award_badge(user_id, "rule_author_3")
        awarded.append("rule_author_3")
    if verified_rules >= 10 and not has_badge(user_id, "rule_author_10"):
        award_badge(user_id, "rule_author_10")
        awarded.append("rule_author_10")

    ratings_count = RuleRating.query.filter_by(user_id=user_id).count()
    if ratings_count >= 5 and not has_badge(user_id, "peer_reviewer_5"):
        award_badge(user_id, "peer_reviewer_5")
        awarded.append("peer_reviewer_5")

    categories = db.session.query(CommunityRule.category).filter_by(
        author_id=user_id, is_verified=True
    ).distinct().all()
    if len(categories) >= 6 and not has_badge(user_id, "all_categories"):
        award_badge(user_id, "all_categories")
        awarded.append("all_categories")

    recalculate_tier(user_id)
    return awarded


def recalculate_tier(user_id):
    profile = CommunityProfile.query.filter_by(user_id=user_id).first()
    if not profile:
        return

    badges = UserBadge.query.filter_by(user_id=user_id).all()
    badge_keys = {b.badge_key for b in badges}

    sentinel_badges = {"savings_10000"}
    operator_badges = {"savings_1000", "rule_author_10", "all_categories"}
    breaker_badges = {"rule_author_1", "rule_author_3", "scenario_contributor", "savings_100", "peer_reviewer_5"}

    if badge_keys & sentinel_badges and profile.total_points >= 300:
        profile.tier = TIER_SENTINEL_PRIME
    elif badge_keys & operator_badges and profile.total_points >= 150:
        profile.tier = TIER_GRID_OPERATOR
    elif badge_keys & breaker_badges and profile.total_points >= 50:
        profile.tier = TIER_CIRCUIT_BREAKER
    else:
        profile.tier = TIER_FUSE_APPRENTICE

    db.session.commit()


def get_leaderboard(limit=50):
    profiles = CommunityProfile.query.filter_by(opted_in=True).order_by(
        CommunityProfile.total_points.desc(),
        CommunityProfile.tier.desc(),
    ).limit(limit).all()
    return [p.to_dict() for p in profiles]


def get_wall_of_fame():
    sentinels = CommunityProfile.query.filter_by(is_founding_sentinel=True).order_by(
        CommunityProfile.joined_at.asc()
    ).limit(FOUNDING_SENTINEL_LIMIT).all()
    return [s.to_dict() for s in sentinels]


def get_user_badges(user_id):
    badges = UserBadge.query.filter_by(user_id=user_id).order_by(UserBadge.earned_at.desc()).all()
    return [b.to_dict() for b in badges]
