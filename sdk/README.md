# Snapwire Python SDK

Official Python SDK for [Snapwire](https://github.com/snapwire-ai/snapwire) — The Safety Fuse for Your AI Agents.

## Installation

```bash
pip install snapwire
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

# Automatically checked by Snapwire before execution
result = query_database("SELECT * FROM users")
```

## Health Check

```python
health = fw.check_health()
print(health)
```
