"""
Snapwire Rule Validation Suite

Runs all rules in the /rules/ directory against the attack scenario suite.
Each implemented rule is tested against every scenario to verify it correctly
blocks threats and allows safe calls.

Usage:
    python -m pytest tests/scenarios/test_rules.py -v
    python -m pytest tests/scenarios/test_rules.py -v -k "env_protection"
    python -m pytest tests/scenarios/test_rules.py -v -k "credential"
"""

import importlib
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tests.scenarios.attack_scenarios import SCENARIOS, get_categories


def _load_rules():
    rules_dir = os.path.join(os.path.dirname(__file__), "..", "..", "rules")
    rules = {}
    for filename in sorted(os.listdir(rules_dir)):
        if filename.endswith(".py") and filename != "__init__.py":
            module_name = filename[:-3]
            try:
                spec = importlib.util.spec_from_file_location(
                    f"rules.{module_name}",
                    os.path.join(rules_dir, filename)
                )
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "evaluate"):
                    doc = (mod.__doc__ or "").upper()
                    is_stub = "NOT YET IMPLEMENTED" in doc or "STUB" in doc
                    rules[module_name] = {"module": mod, "is_stub": is_stub}
            except Exception as e:
                print(f"Warning: Could not load rule '{module_name}': {e}")
    return rules


RULES = _load_rules()
IMPLEMENTED_RULES = {k: v for k, v in RULES.items() if not v["is_stub"]}
STUB_RULES = {k: v for k, v in RULES.items() if v["is_stub"]}

CATEGORY_RULE_MAP = {
    "credential_exfil": "env_protection",
    "env_access": "env_protection",
    "pii_leakage": "block_pii",
    "crypto_transaction": "crypto_lock",
    "domain_exfil": "domain_allowlist",
}


class TestEnvProtection:
    """Tests for the env_protection rule (IMPLEMENTED)."""

    @pytest.fixture
    def rule(self):
        if "env_protection" not in IMPLEMENTED_RULES:
            pytest.skip("env_protection rule not implemented")
        return IMPLEMENTED_RULES["env_protection"]["module"]

    @pytest.mark.parametrize(
        "scenario",
        [s for s in SCENARIOS if s["category"] in ("credential_exfil", "env_access")],
        ids=lambda s: f"{s['id']}-{s['name']}"
    )
    def test_blocks_dangerous_calls(self, rule, scenario):
        result = rule.evaluate(scenario["tool_name"], scenario["parameters"])
        assert result["allowed"] is False, (
            f"env_protection should block '{scenario['name']}' "
            f"({scenario['description']}), got: {result}"
        )

    @pytest.mark.parametrize(
        "scenario",
        [s for s in SCENARIOS if s["category"] == "safe_calls"],
        ids=lambda s: f"{s['id']}-{s['name']}"
    )
    def test_allows_safe_calls(self, rule, scenario):
        result = rule.evaluate(scenario["tool_name"], scenario["parameters"])
        assert result["allowed"] is True, (
            f"env_protection should allow '{scenario['name']}' "
            f"({scenario['description']}), got: {result}"
        )


class TestStubRules:
    """Verify stub rules load and return valid responses (even if not implemented)."""

    @pytest.mark.parametrize(
        "rule_name",
        list(STUB_RULES.keys()),
        ids=lambda n: n
    )
    def test_stub_returns_valid_response(self, rule_name):
        mod = STUB_RULES[rule_name]["module"]
        result = mod.evaluate("test_tool", {"param": "value"})
        assert isinstance(result, dict), f"{rule_name} should return a dict"
        assert "allowed" in result, f"{rule_name} result missing 'allowed' key"
        assert "reason" in result, f"{rule_name} result missing 'reason' key"
        assert "rule" in result, f"{rule_name} result missing 'rule' key"

    @pytest.mark.parametrize(
        "rule_name",
        list(STUB_RULES.keys()),
        ids=lambda n: n
    )
    def test_stub_passes_by_default(self, rule_name):
        mod = STUB_RULES[rule_name]["module"]
        result = mod.evaluate("test_tool", {"param": "value"})
        assert result["allowed"] is True, (
            f"Stub rule '{rule_name}' should default to allowed=True "
            f"until implemented"
        )


class TestAllRulesInterface:
    """Verify every rule in /rules/ follows the evaluate() interface."""

    @pytest.mark.parametrize(
        "rule_name",
        list(RULES.keys()),
        ids=lambda n: n
    )
    def test_evaluate_accepts_tool_name_and_parameters(self, rule_name):
        mod = RULES[rule_name]["module"]
        result = mod.evaluate("some_tool", {"key": "value"})
        assert isinstance(result, dict)
        assert "allowed" in result
        assert isinstance(result["allowed"], bool)

    @pytest.mark.parametrize(
        "rule_name",
        list(RULES.keys()),
        ids=lambda n: n
    )
    def test_evaluate_handles_empty_parameters(self, rule_name):
        mod = RULES[rule_name]["module"]
        result = mod.evaluate("some_tool", {})
        assert isinstance(result, dict)
        assert "allowed" in result


class TestScenarioCoverage:
    """Meta-tests to verify scenario suite coverage."""

    def test_has_minimum_scenarios(self):
        assert len(SCENARIOS) >= 20, (
            f"Expected at least 20 scenarios, got {len(SCENARIOS)}"
        )

    def test_covers_all_categories(self):
        expected = {"credential_exfil", "env_access", "pii_leakage",
                    "crypto_transaction", "domain_exfil", "safe_calls"}
        actual = set(s["category"] for s in SCENARIOS)
        assert expected.issubset(actual), (
            f"Missing categories: {expected - actual}"
        )

    def test_has_safe_scenarios(self):
        safe = [s for s in SCENARIOS if s["should_block"] is False]
        assert len(safe) >= 3, (
            f"Expected at least 3 safe scenarios, got {len(safe)}"
        )

    def test_has_block_scenarios(self):
        blocked = [s for s in SCENARIOS if s["should_block"] is True]
        assert len(blocked) >= 10, (
            f"Expected at least 10 block scenarios, got {len(blocked)}"
        )

    def test_all_scenarios_have_required_fields(self):
        required = {"id", "name", "category", "tool_name", "parameters",
                    "should_block", "description"}
        for scenario in SCENARIOS:
            missing = required - set(scenario.keys())
            assert not missing, (
                f"Scenario '{scenario.get('id', '?')}' missing fields: {missing}"
            )

    def test_unique_scenario_ids(self):
        ids = [s["id"] for s in SCENARIOS]
        assert len(ids) == len(set(ids)), "Duplicate scenario IDs found"
