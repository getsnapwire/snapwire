# Agentic Firewall Python SDK

Official Python SDK for the [Agentic Firewall](https://github.com/agenticfirewall/agentic-firewall) - security firewall for AI agents.

## Installation

```bash
pip install agentic-firewall
```

## Quick Start

```python
from agentic_firewall import AgenticFirewall

fw = AgenticFirewall(
    api_key="your-api-key",
    url="https://your-server.com"
)

# Intercept a tool call
result = fw.intercept(
    tool_name="send_email",
    parameters={"to": "user@example.com", "body": "Hello"},
    agent_id="my-agent"
)

if result.allowed:
    print("Tool call approved")
else:
    print(f"Blocked: {result.reason}")
```

## Wrapping Tools

```python
@fw.wrap_tool("database_query", agent_id="data-agent")
def query_database(sql):
    return db.execute(sql)

# Automatically checked by firewall before execution
result = query_database("SELECT * FROM users")
```

## Health Check

```python
health = fw.check_health()
print(health)
```
