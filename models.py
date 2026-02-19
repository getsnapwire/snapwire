import hashlib
import json
import uuid
from datetime import datetime
from app import db
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin
from flask_login import UserMixin
from sqlalchemy import UniqueConstraint


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=True)
    first_name = db.Column(db.String, nullable=True)
    last_name = db.Column(db.String, nullable=True)
    profile_image_url = db.Column(db.String, nullable=True)
    password_hash = db.Column(db.String, nullable=True)
    auth_provider = db.Column(db.String, default='replit')
    role = db.Column(db.String, default='admin', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    active_tenant_id = db.Column(db.String, nullable=True)
    active_tenant_type = db.Column(db.String, default='personal')
    display_name = db.Column(db.String, nullable=True)
    onboarded = db.Column(db.Boolean, default=False)
    tos_accepted_at = db.Column(db.DateTime, nullable=True)
    onboarding_completed_at = db.Column(db.DateTime, nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(128), nullable=True)
    email_verification_sent_at = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(128), nullable=True)
    password_reset_expires_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.String, db.ForeignKey(User.id))
    browser_session_key = db.Column(db.String, nullable=False)
    user = db.relationship(User)
    __table_args__ = (UniqueConstraint(
        'user_id',
        'browser_session_key',
        'provider',
        name='uq_user_browser_session_key_provider',
    ),)


class ApiKey(db.Model):
    __tablename__ = 'api_keys'
    id = db.Column(db.String, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    tenant_id = db.Column(db.String, nullable=True, index=True)
    name = db.Column(db.String, nullable=False)
    key_hash = db.Column(db.String, nullable=False)
    key_prefix = db.Column(db.String(8), nullable=False)
    agent_name = db.Column(db.String, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    user = db.relationship('User', backref='api_keys')


class AuditLogEntry(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4())[:8])
    tenant_id = db.Column(db.String, nullable=True, index=True)
    tool_name = db.Column(db.String, nullable=False)
    tool_params = db.Column(db.Text, nullable=True)
    intent = db.Column(db.Text, nullable=True)
    context = db.Column(db.Text, nullable=True)
    status = db.Column(db.String, nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    violations_json = db.Column(db.Text, nullable=True)
    analysis = db.Column(db.Text, nullable=True)
    chain_of_thought = db.Column(db.Text, nullable=True)
    agent_id = db.Column(db.String, default='unknown')
    api_key_id = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        import json
        violations = []
        if self.violations_json:
            try:
                violations = json.loads(self.violations_json)
            except Exception:
                pass
        params = {}
        if self.tool_params:
            try:
                params = json.loads(self.tool_params)
            except Exception:
                pass
        cot = None
        if self.chain_of_thought:
            try:
                cot = json.loads(self.chain_of_thought)
            except Exception:
                cot = self.chain_of_thought
        return {
            "id": self.id,
            "tool_call": {
                "tool_name": self.tool_name,
                "parameters": params,
                "intent": self.intent or "",
                "context": self.context or "",
            },
            "audit_result": {
                "violations": violations,
                "risk_score": self.risk_score,
                "analysis": self.analysis or "",
                "allowed": self.status in ("allowed", "approved", "auto-approved"),
                "chain_of_thought": cot,
            },
            "status": self.status,
            "agent_id": self.agent_id,
            "api_key_id": self.api_key_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class PendingAction(db.Model):
    __tablename__ = 'pending_actions'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4())[:8])
    tenant_id = db.Column(db.String, nullable=True, index=True)
    tool_name = db.Column(db.String, nullable=False)
    tool_params = db.Column(db.Text, nullable=True)
    intent = db.Column(db.Text, nullable=True)
    context = db.Column(db.Text, nullable=True)
    status = db.Column(db.String, default='pending')
    risk_score = db.Column(db.Integer, default=0)
    violations_json = db.Column(db.Text, nullable=True)
    analysis = db.Column(db.Text, nullable=True)
    agent_id = db.Column(db.String, default='unknown')
    api_key_id = db.Column(db.String, nullable=True)
    webhook_url = db.Column(db.String, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        import json
        violations = []
        if self.violations_json:
            try:
                violations = json.loads(self.violations_json)
            except Exception:
                pass
        params = {}
        if self.tool_params:
            try:
                params = json.loads(self.tool_params)
            except Exception:
                pass
        return {
            "id": self.id,
            "tool_call": {
                "tool_name": self.tool_name,
                "parameters": params,
                "intent": self.intent or "",
                "context": self.context or "",
            },
            "audit_result": {
                "violations": violations,
                "risk_score": self.risk_score,
                "analysis": self.analysis or "",
                "allowed": False,
            },
            "status": self.status,
            "agent_id": self.agent_id,
            "api_key_id": self.api_key_id,
            "webhook_url": self.webhook_url,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AutoApproveCount(db.Model):
    __tablename__ = 'auto_approve_counts'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=True, index=True)
    rule_name = db.Column(db.String, nullable=False)
    agent_id = db.Column(db.String, nullable=False)
    consecutive_approvals = db.Column(db.Integer, default=0)
    __table_args__ = (UniqueConstraint('rule_name', 'agent_id', name='uq_rule_agent'),)


class WebhookConfig(db.Model):
    __tablename__ = 'webhook_configs'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4())[:8])
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    tenant_id = db.Column(db.String, nullable=True, index=True)
    name = db.Column(db.String, nullable=False)
    url = db.Column(db.String, nullable=False)
    agent_filter = db.Column(db.String, nullable=True)
    event_types = db.Column(db.String, default='all')
    is_active = db.Column(db.Boolean, default=True)
    last_triggered_at = db.Column(db.DateTime, nullable=True)
    trigger_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class RuleVersion(db.Model):
    __tablename__ = 'rule_versions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=True, index=True)
    rule_name = db.Column(db.String, nullable=False)
    action = db.Column(db.String, nullable=False)
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    old_config = db.Column(db.Text, nullable=True)
    new_config = db.Column(db.Text, nullable=True)
    changed_by = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        import json
        old_cfg = None
        new_cfg = None
        if self.old_config:
            try:
                old_cfg = json.loads(self.old_config)
            except Exception:
                old_cfg = self.old_config
        if self.new_config:
            try:
                new_cfg = json.loads(self.new_config)
            except Exception:
                new_cfg = self.new_config
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "action": self.action,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "old_config": old_cfg,
            "new_config": new_cfg,
            "changed_by": self.changed_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Organization(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4())[:8])
    name = db.Column(db.String, nullable=False)
    slug = db.Column(db.String, unique=True, nullable=False)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator = db.relationship('User', backref='created_orgs')


class OrgMembership(db.Model):
    __tablename__ = 'org_memberships'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    org_id = db.Column(db.String, db.ForeignKey('organizations.id'), nullable=False)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String, default='member', nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint('org_id', 'user_id', name='uq_org_user'),)
    org = db.relationship('Organization', backref='memberships')
    user = db.relationship('User', backref='org_memberships')


class ConstitutionRule(db.Model):
    __tablename__ = 'constitution_rules'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    rule_name = db.Column(db.String, nullable=False)
    value = db.Column(db.Text, nullable=False)
    display_name = db.Column(db.String, nullable=True)
    description = db.Column(db.Text, nullable=True)
    hint = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String, default='medium')
    mode = db.Column(db.String, default='enforce')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    __table_args__ = (UniqueConstraint('tenant_id', 'rule_name', name='uq_tenant_rule'),)


class NotificationSetting(db.Model):
    __tablename__ = 'notification_settings'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, unique=True, nullable=False)
    slack_webhook_url = db.Column(db.String, default='')
    notify_on_block = db.Column(db.Boolean, default=True)
    notify_on_critical = db.Column(db.Boolean, default=False)
    notify_threshold_risk_score = db.Column(db.Integer, default=70)
    email_enabled = db.Column(db.Boolean, default=False)
    email_address = db.Column(db.String, default='')
    email_on_block = db.Column(db.Boolean, default=True)
    email_on_critical = db.Column(db.Boolean, default=True)
    email_digest = db.Column(db.Boolean, default=False)


class UsageRecord(db.Model):
    __tablename__ = 'usage_records'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    month = db.Column(db.String, nullable=False)
    api_calls = db.Column(db.Integer, default=0)
    __table_args__ = (UniqueConstraint('tenant_id', 'month', name='uq_tenant_month'),)


class ToolCatalog(db.Model):
    __tablename__ = 'tool_catalog'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    tool_name = db.Column(db.String, nullable=False)
    safety_grade = db.Column(db.String(1), default='U')
    status = db.Column(db.String, default='pending_review')
    description = db.Column(db.Text, nullable=True)
    safety_analysis = db.Column(db.Text, nullable=True)
    auto_approve = db.Column(db.Boolean, default=False)
    reviewed_by = db.Column(db.String, nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    call_count = db.Column(db.Integer, default=0)
    schema_json = db.Column(db.Text, nullable=True)
    schema_enforcement = db.Column(db.String(10), default='flexible')
    __table_args__ = (UniqueConstraint('tenant_id', 'tool_name', name='uq_tenant_tool'),)

    def to_dict(self):
        schema_parsed = None
        if self.schema_json:
            try:
                schema_parsed = json.loads(self.schema_json)
            except Exception:
                schema_parsed = None
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "safety_grade": self.safety_grade,
            "status": self.status,
            "description": self.description,
            "safety_analysis": self.safety_analysis,
            "auto_approve": self.auto_approve,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "call_count": self.call_count,
            "schema": schema_parsed,
            "schema_enforcement": self.schema_enforcement,
        }


class BlastRadiusConfig(db.Model):
    __tablename__ = 'blast_radius_config'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, unique=True, nullable=False)
    max_calls = db.Column(db.Integer, default=5)
    window_seconds = db.Column(db.Integer, default=60)
    enabled = db.Column(db.Boolean, default=True)
    lockout_seconds = db.Column(db.Integer, default=300)
    max_spend_per_session = db.Column(db.Float, default=20.0)
    require_manual_reset = db.Column(db.Boolean, default=True)


class BlastRadiusEvent(db.Model):
    __tablename__ = 'blast_radius_events'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    agent_id = db.Column(db.String, nullable=False)
    api_key_id = db.Column(db.String, nullable=True)
    triggered_at = db.Column(db.DateTime, default=datetime.utcnow)
    call_count = db.Column(db.Integer, default=0)
    window_seconds = db.Column(db.Integer, default=60)
    trigger_type = db.Column(db.String, default='rate')
    spend_amount = db.Column(db.Float, nullable=True)


class VaultEntry(db.Model):
    __tablename__ = 'vault_entries'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    tool_name = db.Column(db.String, nullable=False)
    secret_key = db.Column(db.String, nullable=False)
    header_name = db.Column(db.String, default='Authorization')
    header_prefix = db.Column(db.String, default='Bearer ')
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint('tenant_id', 'tool_name', name='uq_tenant_vault_tool'),)

    def to_dict(self):
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "secret_key": self.secret_key,
            "header_name": self.header_name,
            "header_prefix": self.header_prefix,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class HoneypotTool(db.Model):
    __tablename__ = 'honeypot_tools'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    tool_name = db.Column(db.String, nullable=False)
    description = db.Column(db.Text, nullable=True)
    alert_message = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    trigger_count = db.Column(db.Integer, default=0)
    last_triggered_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint('tenant_id', 'tool_name', name='uq_tenant_honeypot'),)

    def to_dict(self):
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "description": self.description,
            "alert_message": self.alert_message,
            "is_active": self.is_active,
            "trigger_count": self.trigger_count,
            "last_triggered_at": self.last_triggered_at.isoformat() if self.last_triggered_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class HoneypotAlert(db.Model):
    __tablename__ = 'honeypot_alerts'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    honeypot_tool_name = db.Column(db.String, nullable=False)
    agent_id = db.Column(db.String, nullable=False)
    api_key_id = db.Column(db.String, nullable=True)
    tool_params = db.Column(db.Text, nullable=True)
    intent = db.Column(db.Text, nullable=True)
    api_key_locked = db.Column(db.Boolean, default=False)
    triggered_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "honeypot_tool_name": self.honeypot_tool_name,
            "agent_id": self.agent_id,
            "api_key_id": self.api_key_id,
            "tool_params": self.tool_params,
            "intent": self.intent,
            "api_key_locked": self.api_key_locked,
            "triggered_at": self.triggered_at.isoformat() if self.triggered_at else None,
        }


class LoopDetectorEvent(db.Model):
    __tablename__ = 'loop_detector_events'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    agent_id = db.Column(db.String, nullable=False)
    api_key_id = db.Column(db.String, nullable=True)
    tool_name = db.Column(db.String, nullable=False)
    params_hash = db.Column(db.String(32), nullable=True)
    repeat_count = db.Column(db.Integer, default=3)
    estimated_savings = db.Column(db.Float, default=0.0)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "api_key_id": self.api_key_id,
            "tool_name": self.tool_name,
            "params_hash": self.params_hash,
            "repeat_count": self.repeat_count,
            "estimated_savings": self.estimated_savings,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
        }


class SchemaViolationEvent(db.Model):
    __tablename__ = 'schema_violation_events'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    tool_name = db.Column(db.String, nullable=False)
    enforcement_mode = db.Column(db.String(10), default='flexible')
    violation_count = db.Column(db.Integer, default=0)
    violations_json = db.Column(db.Text, nullable=True)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "enforcement_mode": self.enforcement_mode,
            "violation_count": self.violation_count,
            "violations": json.loads(self.violations_json) if self.violations_json else [],
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
        }


class TenantSettings(db.Model):
    __tablename__ = 'tenant_settings'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, unique=True, nullable=False, index=True)
    shadow_mode = db.Column(db.Boolean, default=True, nullable=False)
    shadow_mode_changed_at = db.Column(db.DateTime, nullable=True)
    shadow_mode_changed_by = db.Column(db.String, nullable=True)
    auto_install_starter_rules = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class InstallConfig(db.Model):
    __tablename__ = 'install_config'
    id = db.Column(db.Integer, primary_key=True)
    install_id = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    telemetry_enabled = db.Column(db.Boolean, default=False)
    version = db.Column(db.String(20), default='1.0.0')


class TelemetryPing(db.Model):
    __tablename__ = 'telemetry_pings'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    install_id = db.Column(db.String(64), nullable=False, index=True)
    version = db.Column(db.String(20), nullable=True)
    platform = db.Column(db.String(50), nullable=True)
    total_rules = db.Column(db.Integer, default=0)
    total_intercepts_24h = db.Column(db.Integer, default=0)
    total_agents = db.Column(db.Integer, default=0)
    uptime_hours = db.Column(db.Float, default=0)
    received_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "install_id": self.install_id,
            "version": self.version,
            "platform": self.platform,
            "total_rules": self.total_rules,
            "total_intercepts_24h": self.total_intercepts_24h,
            "total_agents": self.total_agents,
            "uptime_hours": self.uptime_hours,
            "received_at": self.received_at.isoformat() if self.received_at else None,
        }


class SelfHostedInstall(db.Model):
    __tablename__ = 'self_hosted_installs'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    company = db.Column(db.String, nullable=True)
    use_case = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String, nullable=True)
    template_clicked = db.Column(db.Boolean, default=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "company": self.company,
            "use_case": self.use_case,
            "template_clicked": self.template_clicked,
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
        }


class ProxyToken(db.Model):
    __tablename__ = 'proxy_tokens'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    vault_entry_id = db.Column(db.Integer, db.ForeignKey('vault_entries.id'), nullable=False)
    label = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    last_used_at = db.Column(db.DateTime, nullable=True)
    use_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    revoked_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "token": self.token,
            "vault_entry_id": self.vault_entry_id,
            "label": self.label,
            "is_active": self.is_active,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "use_count": self.use_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }


class RiskSignal(db.Model):
    __tablename__ = 'risk_signals'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String, nullable=False, index=True)
    tool_name = db.Column(db.String, nullable=False)
    score = db.Column(db.Integer, default=50)
    grade = db.Column(db.String(1), default='C')
    signals_json = db.Column(db.Text, nullable=True)
    source_url = db.Column(db.String, nullable=True)
    assessed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "score": self.score,
            "grade": self.grade,
            "signals": json.loads(self.signals_json) if self.signals_json else [],
            "source_url": self.source_url,
            "assessed_at": self.assessed_at.isoformat() if self.assessed_at else None,
            "disclaimer": "Intelligence Signals are probabilistic and for informational use only. Final action remains User responsibility.",
        }


class PublicAudit(db.Model):
    __tablename__ = 'public_audits'
    id = db.Column(db.Integer, primary_key=True)
    prompt_hash = db.Column(db.String, nullable=False)
    prompt_preview = db.Column(db.String(200), nullable=True)
    safety_score = db.Column(db.Integer, nullable=True)
    vulnerabilities_json = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String, nullable=True)
    converted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "prompt_preview": self.prompt_preview,
            "safety_score": self.safety_score,
            "vulnerabilities": json.loads(self.vulnerabilities_json) if self.vulnerabilities_json else [],
            "converted": self.converted,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
