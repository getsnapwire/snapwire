"""
Snapwire Example Agent — Minimal tool-call routed through Sentinel.

Usage:
    # Start the Sentinel proxy first:
    #   python -m sentinel

    # Then run this agent through the proxy:
    OPENAI_BASE_URL=http://localhost:8080/v1 python examples/basic_agent.py

    # Check the Snapwire dashboard to see the intercepted tool call.
"""

import json
import os
import urllib.request

base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
api_key = os.environ.get("OPENAI_API_KEY", "sk-test-placeholder")

payload = {
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "What is the weather in London?"}],
    "tools": [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get the current weather for a city",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string", "description": "City name"}
                    },
                    "required": ["city"],
                },
            },
        }
    ],
}

url = f"{base_url}/chat/completions"
data = json.dumps(payload).encode()
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_key}",
}

req = urllib.request.Request(url, data=data, headers=headers)

print(f"Sending tool-call request to: {url}")
print(f"Tool: get_weather(city='London')")
print()

try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.loads(resp.read())
        print(f"Status: {resp.status}")
        print(f"Response: {json.dumps(body, indent=2)[:500]}")
except urllib.error.HTTPError as e:
    print(f"Status: {e.code}")
    body = e.read().decode()
    print(f"Response: {body[:500]}")
except urllib.error.URLError as e:
    print(f"Connection error: {e.reason}")
    print("Is the Sentinel proxy running? Start it with: python -m sentinel")
