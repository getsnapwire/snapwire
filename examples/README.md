# Snapwire Examples

## basic_agent.py

A minimal ~20-line agent that sends an OpenAI-format tool call through the Sentinel proxy. This demonstrates how any existing agent can be governed by Snapwire with a single environment variable change.

### Prerequisites

1. Start the Snapwire app:
   ```bash
   python main.py
   ```

2. Start the Sentinel proxy (separate terminal):
   ```bash
   python -m sentinel
   ```

### Run

```bash
OPENAI_BASE_URL=http://localhost:8080/v1 python examples/basic_agent.py
```

The Sentinel proxy will intercept the tool call, log it to Snapwire for governance checks, and forward it upstream. Check the Snapwire dashboard at `http://localhost:5000` to see the intercepted call.

### What Happens

1. The agent sends a `get_weather` tool call to the proxy
2. Sentinel detects the OpenAI-format tool definition
3. The call is forwarded to Snapwire's `/intercept` API for governance
4. Headers (`X-Snapwire-Trace`, `X-Snapwire-Gov`) are injected
5. The request is forwarded to the upstream API

### Key Point

No SDK required. No code changes. Just set `OPENAI_BASE_URL` and your agent is governed.

## Other Examples

- `sample_logs.json` — Sample tool-call logs for testing the intercept API
- `sample_agent_log.json` — Single agent session log
- `sample_agent_log.jsonl` — Streaming agent log format
- `sample_nested_log.json` — Nested tool-call structure
