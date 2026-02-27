"""Tests for the Sentinel Proxy protocol detector and configuration."""

import unittest
import json
from sentinel.detector import (
    detect_tool_calls,
    detect_openai,
    detect_anthropic,
    detect_mcp_jsonrpc,
    detect_a2a,
    detect_generic_jsonrpc,
    DetectedToolCall,
    PROTOCOL_REGISTRY,
)


class TestOpenAIDetector(unittest.TestCase):
    def test_tools_array(self):
        body = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hello"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
                    },
                }
            ],
        }
        results = detect_openai(body)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].tool_name, "get_weather")
        self.assertEqual(results[0].protocol, "openai")
        self.assertGreaterEqual(results[0].confidence, 0.9)

    def test_tool_choice(self):
        body = {
            "model": "gpt-4",
            "tool_choice": {"type": "function", "function": {"name": "search"}},
        }
        results = detect_openai(body)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].tool_name, "search")

    def test_tool_calls_in_messages(self):
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_123",
                            "type": "function",
                            "function": {"name": "write_file", "arguments": '{"path": "test.py"}'},
                        }
                    ],
                }
            ]
        }
        results = detect_openai(body)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].tool_name, "write_file")
        self.assertEqual(results[0].parameters, {"path": "test.py"})

    def test_no_tools(self):
        body = {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}
        results = detect_openai(body)
        self.assertEqual(len(results), 0)


class TestAnthropicDetector(unittest.TestCase):
    def test_tools_definition(self):
        body = {
            "model": "claude-sonnet-4-5",
            "tools": [
                {"name": "calculator", "input_schema": {"type": "object", "properties": {"expression": {"type": "string"}}}},
            ],
            "messages": [{"role": "user", "content": "calculate 2+2"}],
        }
        results = detect_anthropic(body)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].tool_name, "calculator")
        self.assertEqual(results[0].protocol, "anthropic")

    def test_tool_use_block(self):
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "toolu_123", "name": "bash", "input": {"command": "ls"}},
                    ],
                }
            ]
        }
        results = detect_anthropic(body)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].tool_name, "bash")
        self.assertEqual(results[0].parameters, {"command": "ls"})

    def test_no_tools(self):
        body = {"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "hi"}]}
        results = detect_anthropic(body)
        self.assertEqual(len(results), 0)


class TestMCPDetector(unittest.TestCase):
    def test_tools_call(self):
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}},
            "id": 1,
        }
        results = detect_mcp_jsonrpc(body)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].tool_name, "read_file")
        self.assertEqual(results[0].protocol, "mcp")
        self.assertEqual(results[0].confidence, 1.0)

    def test_non_tool_method(self):
        body = {"jsonrpc": "2.0", "method": "resources/list", "id": 1}
        results = detect_mcp_jsonrpc(body)
        self.assertEqual(len(results), 0)


class TestA2ADetector(unittest.TestCase):
    def test_tasks_send(self):
        body = {
            "jsonrpc": "2.0",
            "method": "tasks/send",
            "params": {
                "id": "task-123",
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "Deploy the application"}],
                },
            },
            "id": 1,
        }
        results = detect_a2a(body)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].tool_name, "tasks/send")
        self.assertEqual(results[0].protocol, "a2a")

    def test_delegate_task(self):
        body = {
            "jsonrpc": "2.0",
            "method": "delegate_task",
            "params": {"task": "review_code"},
            "id": 1,
        }
        results = detect_a2a(body)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].tool_name, "delegate_task")


class TestGenericJSONRPC(unittest.TestCase):
    def test_tools_prefix(self):
        body = {"jsonrpc": "2.0", "method": "tools/execute", "params": {"name": "test"}, "id": 1}
        results = detect_generic_jsonrpc(body)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].confidence, 0.8)

    def test_generic_method(self):
        body = {"jsonrpc": "2.0", "method": "custom.method", "params": {"key": "value"}, "id": 1}
        results = detect_generic_jsonrpc(body)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].confidence, 0.5)

    def test_not_jsonrpc(self):
        body = {"method": "something", "params": {}}
        results = detect_generic_jsonrpc(body)
        self.assertEqual(len(results), 0)


class TestDetectToolCalls(unittest.TestCase):
    def test_empty_body(self):
        self.assertEqual(detect_tool_calls({}), [])
        self.assertEqual(detect_tool_calls(None), [])
        self.assertEqual(detect_tool_calls("string"), [])
        self.assertEqual(detect_tool_calls([]), [])

    def test_plain_chat_request(self):
        body = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "What is 2+2?"}],
        }
        results = detect_tool_calls(body)
        self.assertEqual(len(results), 0)

    def test_combined_detection(self):
        body = {
            "model": "gpt-4",
            "tools": [
                {"type": "function", "function": {"name": "search", "parameters": {}}},
                {"type": "function", "function": {"name": "calculate", "parameters": {}}},
            ],
        }
        results = detect_tool_calls(body)
        self.assertEqual(len(results), 2)
        names = {r.tool_name for r in results}
        self.assertIn("search", names)
        self.assertIn("calculate", names)

    def test_deduplication(self):
        body = {
            "tools": [{"type": "function", "function": {"name": "search", "parameters": {}}}],
            "tool_choice": {"type": "function", "function": {"name": "search"}},
        }
        results = detect_tool_calls(body)
        openai_results = [r for r in results if r.protocol == "openai"]
        search_count = sum(1 for r in openai_results if r.tool_name == "search")
        self.assertEqual(search_count, 1)


class TestProtocolRegistry(unittest.TestCase):
    def test_registry_has_all_protocols(self):
        self.assertGreaterEqual(len(PROTOCOL_REGISTRY), 5)

    def test_registry_functions_callable(self):
        for fn in PROTOCOL_REGISTRY:
            self.assertTrue(callable(fn))
            result = fn({})
            self.assertIsInstance(result, list)


class TestProxyHardening(unittest.TestCase):
    def test_max_body_size_exists(self):
        from sentinel.proxy import MAX_BODY_SIZE
        self.assertIsInstance(MAX_BODY_SIZE, int)
        self.assertEqual(MAX_BODY_SIZE, 10 * 1024 * 1024)

    def test_max_body_size_reasonable(self):
        from sentinel.proxy import MAX_BODY_SIZE
        self.assertGreaterEqual(MAX_BODY_SIZE, 1 * 1024 * 1024)
        self.assertLessEqual(MAX_BODY_SIZE, 100 * 1024 * 1024)


class TestSentinelConfig(unittest.TestCase):
    def test_get_config_defaults(self):
        import os
        for key in ("SENTINEL_PORT", "UPSTREAM_URL", "SNAPWIRE_URL", "SENTINEL_MODE"):
            os.environ.pop(key, None)

        from sentinel.__main__ import get_config
        config = get_config()
        self.assertEqual(config["port"], 8080)
        self.assertEqual(config["upstream_url"], "https://api.openai.com")
        self.assertEqual(config["snapwire_url"], "http://localhost:5000")
        self.assertEqual(config["mode"], "audit")

    def test_nist_export_grade(self):
        from sentinel.nist_export import _calculate_grade

        grade, note = _calculate_grade({"mode": "enforce"})
        self.assertEqual(grade, "A")
        self.assertIn("Reasonable Care", note)

        grade, note = _calculate_grade({"mode": "audit"})
        self.assertEqual(grade, "B")

        grade, note = _calculate_grade({"mode": "observe"})
        self.assertEqual(grade, "C")
        self.assertIn("Colorado AI Act", note)


if __name__ == "__main__":
    unittest.main()
