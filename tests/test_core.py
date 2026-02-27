import os
import json
import pytest

is_replit = bool(os.environ.get("REPL_ID"))
skip_local_auth = pytest.mark.skipif(is_replit, reason="Local auth not available on Replit")


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "status" in data
        assert "version" in data


class TestAuthFlows:
    def test_login_page_loads(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    @skip_local_auth
    def test_register_creates_user(self, app, client):
        resp = client.post("/auth/register", data={
            "email": "newuser@example.com",
            "name": "New User",
            "password": "securepass123",
            "confirm_password": "securepass123",
        }, follow_redirects=True)
        assert resp.status_code == 200

        with app.app_context():
            from models import User
            user = User.query.filter_by(email="newuser@example.com").first()
            assert user is not None
            assert user.email_verified is False

    @skip_local_auth
    def test_register_password_mismatch(self, client):
        resp = client.post("/auth/register", data={
            "email": "mismatch@example.com",
            "name": "Mismatch",
            "password": "securepass123",
            "confirm_password": "different123",
        })
        assert resp.status_code == 200
        assert b"do not match" in resp.data

    @skip_local_auth
    def test_register_short_password(self, client):
        resp = client.post("/auth/register", data={
            "email": "short@example.com",
            "name": "Short",
            "password": "abc",
            "confirm_password": "abc",
        })
        assert resp.status_code == 200
        assert b"at least 8" in resp.data

    @skip_local_auth
    def test_login_invalid_credentials(self, client):
        resp = client.post("/auth/login", data={
            "email": "nobody@example.com",
            "password": "wrongpass",
        })
        assert resp.status_code == 200
        assert b"Invalid" in resp.data

    @skip_local_auth
    def test_login_valid_credentials(self, app, client):
        with app.app_context():
            from models import User
            from src.tenant import ensure_personal_tenant
            from app import db
            import uuid

            user = User(
                id=str(uuid.uuid4()),
                email="valid@example.com",
                first_name="Valid",
                auth_provider="local",
                role="admin",
                email_verified=True,
            )
            user.set_password("correctpass123")
            db.session.add(user)
            db.session.commit()
            ensure_personal_tenant(user)

        resp = client.post("/auth/login", data={
            "email": "valid@example.com",
            "password": "correctpass123",
        }, follow_redirects=False)
        assert resp.status_code in (200, 302)

    @skip_local_auth
    def test_forgot_password_page(self, client):
        resp = client.get("/auth/forgot-password")
        assert resp.status_code == 200

    @skip_local_auth
    def test_forgot_password_post(self, client):
        resp = client.post("/auth/forgot-password", data={
            "email": "nobody@example.com",
        })
        assert resp.status_code == 200


class TestInterceptAPI:
    def test_intercept_requires_auth(self, client):
        resp = client.post("/api/intercept", json={
            "tool_call": {
                "tool_name": "test_tool",
                "parameters": {},
            }
        })
        assert resp.status_code in (401, 403)

    def test_sentinel_metadata_stored_in_audit_log(self, app, auth_client):
        client, user_id = auth_client
        resp = client.post("/api/intercept", json={
            "tool_name": "read_file",
            "parameters": {"path": "/etc/passwd"},
            "agent_id": "sentinel-test-agent",
            "parent_agent_id": "human-operator",
            "source": "sentinel-proxy",
            "metadata": {
                "protocol": "openai",
                "confidence": 0.95,
                "trace_id": "tr-abc123",
                "proxy_path": "/v1/chat/completions",
                "authorized_by": "ops-team@example.com",
                "hmac_active": True,
            },
        })
        assert resp.status_code in (200, 403, 412, 429)

        from models import AuditLogEntry
        with app.app_context():
            entry = AuditLogEntry.query.filter_by(
                agent_id="sentinel-test-agent"
            ).order_by(AuditLogEntry.created_at.desc()).first()
            assert entry is not None
            cot = json.loads(entry.chain_of_thought)
            assert "sentinel" in cot
            sentinel = cot["sentinel"]
            assert sentinel["trace_id"] == "tr-abc123"
            assert sentinel["authorized_by"] == "ops-team@example.com"
            assert sentinel["hmac_active"] is True
            assert sentinel["protocol"] == "openai"


class TestRulesCRUD:
    def test_get_constitution(self, auth_client):
        client, user_id = auth_client
        resp = client.get("/api/constitution")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "rules" in data

    def test_add_rule(self, auth_client):
        import uuid
        client, user_id = auth_client
        rule_name = f"test_rule_{uuid.uuid4().hex[:8]}"
        resp = client.post("/api/constitution/rules", json={
            "name": rule_name,
            "value": "Never allow file deletion",
            "description": "Prevents destructive file operations",
            "severity": "high",
        })
        assert resp.status_code in (200, 201)

    def test_delete_rule(self, auth_client):
        client, user_id = auth_client
        client.post("/api/constitution/rules", json={
            "name": "delete_test",
            "value": "To be deleted",
            "description": "Test rule for deletion",
            "severity": "medium",
        })
        resp = client.delete("/api/constitution/rules/delete_test")
        assert resp.status_code in (200, 404)


class TestConfigExportImport:
    def test_export_rules(self, auth_client):
        client, user_id = auth_client
        resp = client.post("/api/rules/export")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "metadata" in data or "rules" in data

    def test_import_rules(self, auth_client):
        client, user_id = auth_client
        export_resp = client.post("/api/rules/export")
        if export_resp.status_code == 200:
            export_data = export_resp.get_json()
            resp = client.post("/api/rules/import", json=export_data)
            assert resp.status_code in (200, 400)


class TestTelemetry:
    def test_telemetry_ingest(self, client):
        resp = client.post("/api/telemetry/ingest", json={
            "install_id": "test-install-123",
            "version": "1.0.0",
            "platform": "test",
            "total_rules": 5,
            "total_intercepts_24h": 10,
            "total_agents": 2,
            "uptime_hours": 1.5,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_telemetry_ingest_missing_install_id(self, client):
        resp = client.post("/api/telemetry/ingest", json={
            "version": "1.0.0",
        })
        assert resp.status_code == 400

    def test_telemetry_transparency(self, client):
        resp = client.get("/api/telemetry/transparency")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "what_we_report" in data
        assert "what_we_never_report" in data

    def test_telemetry_dashboard_requires_auth(self, client):
        resp = client.get("/api/admin/telemetry-dashboard")
        assert resp.status_code in (401, 302)

    def test_telemetry_dashboard_with_auth(self, auth_client):
        client, user_id = auth_client
        resp = client.get("/api/admin/telemetry-dashboard")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "install_id" in data
        assert "network" in data


class TestLatencyAnomaly:
    def test_absolute_threshold_triggers_warning(self):
        from src.thinking_sentinel import check_latency_anomaly, _latency_store
        _latency_store.clear()
        result = check_latency_anomaly(35000, agent_id="latency-test", tenant_id="t-lat")
        assert result is not None
        assert result["triggered"] is True
        assert result["elapsed_ms"] == 35000
        assert "absolute threshold" in result["message"]

    def test_rolling_average_triggers_warning(self):
        from src.thinking_sentinel import check_latency_anomaly, _latency_store
        _latency_store.clear()
        for _ in range(5):
            check_latency_anomaly(100, agent_id="avg-test", tenant_id="t-avg")
        result = check_latency_anomaly(500, agent_id="avg-test", tenant_id="t-avg")
        assert result is not None
        assert result["triggered"] is True
        assert "rolling average" in result["message"]

    def test_normal_latency_no_warning(self):
        from src.thinking_sentinel import check_latency_anomaly, _latency_store
        _latency_store.clear()
        for _ in range(5):
            check_latency_anomaly(100, agent_id="norm-test", tenant_id="t-norm")
        result = check_latency_anomaly(110, agent_id="norm-test", tenant_id="t-norm")
        assert result is None


class TestOverview:
    def test_overview_requires_auth(self, client):
        resp = client.get("/api/overview")
        assert resp.status_code in (401, 302)

    def test_overview_with_auth(self, auth_client):
        client, user_id = auth_client
        resp = client.get("/api/overview")
        assert resp.status_code == 200
