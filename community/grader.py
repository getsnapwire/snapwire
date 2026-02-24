import json
import subprocess
import sys
import tempfile
import os

GRADER_SCRIPT = os.path.join(os.path.dirname(__file__), "_grader_runner.py")
MAX_CODE_SIZE = 10000
TIMEOUT_SECONDS = 10
MAX_RULE_LATENCY_MS = 5

ALLOWED_IMPORTS = {"json", "re", "string", "math", "hashlib", "collections", "functools", "itertools", "copy"}

BLOCKED_PATTERNS = ["__import__", "eval(", "exec(", "open(", "compile(", "getattr(", "globals(", "locals(", "__builtins__", "__subclasses__"]


def _check_code_safety(code_string):
    import re as _re
    imports = _re.findall(r'(?:from\s+(\S+)\s+import|import\s+(\S+))', code_string)
    for groups in imports:
        module_name = groups[0] or groups[1]
        base_module = module_name.split('.')[0]
        if base_module not in ALLOWED_IMPORTS:
            return False, f"Blocked import: '{base_module}' is not allowed. Allowed: {', '.join(sorted(ALLOWED_IMPORTS))}"
    for pattern in BLOCKED_PATTERNS:
        if pattern in code_string:
            return False, f"Blocked pattern detected: '{pattern}' is not allowed in community rules"
    return True, None


def grade_rule_code(code_string):
    from tests.scenarios.attack_scenarios import SCENARIOS
    total = len(SCENARIOS)

    if len(code_string) > MAX_CODE_SIZE:
        return {
            "success": False,
            "error": f"Code exceeds maximum size of {MAX_CODE_SIZE} characters",
            "passed": 0,
            "total": total,
            "results": [],
            "pass_rate": 0.0,
        }

    safe, reason = _check_code_safety(code_string)
    if not safe:
        return {
            "success": False,
            "error": reason,
            "passed": 0,
            "total": total,
            "results": [],
            "pass_rate": 0.0,
        }

    if "def evaluate(" not in code_string:
        return {
            "success": False,
            "error": "Rule must define an evaluate(tool_name, parameters) function",
            "passed": 0,
            "total": total,
            "results": [],
            "pass_rate": 0.0,
        }

    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, dir='/tmp') as f:
            f.write(code_string)
            temp_path = f.name

        result = subprocess.run(
            [sys.executable, GRADER_SCRIPT, temp_path],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            cwd=os.path.dirname(os.path.dirname(__file__)),
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": "/tmp",
                "PYTHONPATH": os.path.dirname(os.path.dirname(__file__)),
            },
        )

        os.unlink(temp_path)

        if result.returncode != 0:
            stderr = result.stderr.strip()
            if len(stderr) > 500:
                stderr = stderr[-500:]
            return {
                "success": False,
                "error": f"Rule execution failed: {stderr}",
                "passed": 0,
                "total": total,
                "results": [],
                "pass_rate": 0.0,
            }

        output = json.loads(result.stdout)

        if output.get("success"):
            slow_scenarios = [
                r for r in output.get("results", [])
                if r.get("execution_time_ms", 0) > MAX_RULE_LATENCY_MS
            ]
            if slow_scenarios:
                worst = max(slow_scenarios, key=lambda r: r["execution_time_ms"])
                output["success"] = False
                output["error"] = (
                    f"Your rule was rejected. Latency detected: "
                    f"{worst['execution_time_ms']}ms (Limit: {MAX_RULE_LATENCY_MS}ms). "
                    f"Please optimize your regex/logic and resubmit."
                )

        return output

    except subprocess.TimeoutExpired:
        try:
            os.unlink(temp_path)
        except Exception:
            pass
        return {
            "success": False,
            "error": f"Rule execution timed out after {TIMEOUT_SECONDS} seconds",
            "passed": 0,
            "total": total,
            "results": [],
            "pass_rate": 0.0,
        }
    except json.JSONDecodeError:
        return {
            "success": False,
            "error": "Failed to parse grader output",
            "passed": 0,
            "total": total,
            "results": [],
            "pass_rate": 0.0,
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Grading error: {str(e)}",
            "passed": 0,
            "total": total,
            "results": [],
            "pass_rate": 0.0,
        }
