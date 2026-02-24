"""
Isolated grader runner — executed as a subprocess.
Loads a submitted rule file and runs it against attack scenarios.
Outputs JSON results to stdout.
"""
import json
import sys
import time
import types
import resource

resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
try:
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
except (ValueError, resource.error):
    pass

from tests.scenarios.attack_scenarios import SCENARIOS


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"success": False, "error": "Usage: _grader_runner.py <rule_file>"}))
        sys.exit(1)

    rule_path = sys.argv[1]
    results = []
    passed = 0
    total = len(SCENARIOS)

    try:
        with open(rule_path, 'r') as f:
            code_string = f.read()
    except Exception as e:
        print(json.dumps({"success": False, "error": f"Failed to read rule file: {str(e)}", "passed": 0, "total": total, "results": [], "pass_rate": 0.0}))
        sys.exit(1)

    SAFE_MODULES = {"json", "re", "string", "math", "hashlib", "collections", "functools", "itertools", "copy"}

    _real_import = __import__

    def _safe_import(name, *args, **kwargs):
        if name.split('.')[0] not in SAFE_MODULES:
            raise ImportError(f"Import of '{name}' is not allowed in community rules")
        return _real_import(name, *args, **kwargs)

    try:
        module = types.ModuleType("submitted_rule")
        module.__dict__['__builtins__'] = {
            '__import__': _safe_import,
            'True': True, 'False': False, 'None': None,
            'int': int, 'float': float, 'str': str, 'bool': bool,
            'list': list, 'dict': dict, 'tuple': tuple, 'set': set,
            'len': len, 'range': range, 'enumerate': enumerate,
            'zip': zip, 'map': map, 'filter': filter,
            'min': min, 'max': max, 'sum': sum, 'abs': abs,
            'sorted': sorted, 'reversed': reversed,
            'isinstance': isinstance, 'issubclass': issubclass,
            'hasattr': hasattr, 'type': type,
            'print': lambda *a, **kw: None,
            'repr': repr,
            'ValueError': ValueError, 'TypeError': TypeError,
            'KeyError': KeyError, 'IndexError': IndexError,
            'Exception': Exception,
            'any': any, 'all': all,
        }
        exec(code_string, module.__dict__)
    except Exception as e:
        print(json.dumps({"success": False, "error": f"Failed to load rule: {str(e)}", "passed": 0, "total": total, "results": [], "pass_rate": 0.0}))
        sys.exit(1)

    if not hasattr(module, "evaluate") or not callable(module.evaluate):
        print(json.dumps({"success": False, "error": "Rule must define an evaluate(tool_name, parameters) function", "passed": 0, "total": total, "results": [], "pass_rate": 0.0}))
        sys.exit(1)

    total_start = time.perf_counter()

    for scenario in SCENARIOS:
        try:
            scenario_start = time.perf_counter()
            result = module.evaluate(scenario["tool_name"], scenario["parameters"])
            scenario_end = time.perf_counter()
            execution_time_ms = round((scenario_end - scenario_start) * 1000, 3)

            was_blocked = not result.get("allowed", True)
            expected_block = scenario["should_block"]
            correct = was_blocked == expected_block

            if correct:
                passed += 1

            results.append({
                "id": scenario["id"],
                "name": scenario["name"],
                "category": scenario["category"],
                "expected": "block" if expected_block else "allow",
                "actual": "blocked" if was_blocked else "allowed",
                "correct": correct,
                "reason": result.get("reason", ""),
                "execution_time_ms": execution_time_ms,
            })
        except Exception as e:
            results.append({
                "id": scenario["id"],
                "name": scenario["name"],
                "category": scenario["category"],
                "expected": "block" if scenario["should_block"] else "allow",
                "actual": "error",
                "correct": False,
                "reason": f"Error: {str(e)}",
                "execution_time_ms": 0.0,
            })

    total_end = time.perf_counter()
    total_execution_time_ms = round((total_end - total_start) * 1000, 3)
    latency_values = [r["execution_time_ms"] for r in results if r["execution_time_ms"] > 0]
    avg_latency_ms = round(sum(latency_values) / len(latency_values), 3) if latency_values else 0.0

    pass_rate = (passed / total * 100) if total > 0 else 0
    output = {
        "success": pass_rate == 100,
        "passed": passed,
        "total": total,
        "pass_rate": round(pass_rate, 1),
        "results": results,
        "error": None,
        "total_execution_time_ms": total_execution_time_ms,
        "avg_latency_ms": avg_latency_ms,
    }
    print(json.dumps(output))
    sys.exit(0)


if __name__ == "__main__":
    main()
