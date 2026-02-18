import hashlib
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
    role = db.Column(db.String, default='admin', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)


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
    tool_name = db.Column(db.String, nullable=False)
    tool_params = db.Column(db.Text, nullable=True)
    intent = db.Column(db.Text, nullable=True)
    context = db.Column(db.Text, nullable=True)
    status = db.Column(db.String, nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    violations_json = db.Column(db.Text, nullable=True)
    analysis = db.Column(db.Text, nullable=True)
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
            },
            "status": self.status,
            "agent_id": self.agent_id,
            "api_key_id": self.api_key_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class PendingAction(db.Model):
    __tablename__ = 'pending_actions'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4())[:8])
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
    rule_name = db.Column(db.String, nullable=False)
    agent_id = db.Column(db.String, nullable=False)
    consecutive_approvals = db.Column(db.Integer, default=0)
    __table_args__ = (UniqueConstraint('rule_name', 'agent_id', name='uq_rule_agent'),)


class RuleVersion(db.Model):
    __tablename__ = 'rule_versions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
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
