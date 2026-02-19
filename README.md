# ⚡ Snapwire

The Safety Fuse for Your AI Agents — intercept, audit, and control tool calls in real-time.

## Features

- **Constitutional AI Auditing**: Real-time evaluation of agent tool calls against security rules
- **Shadow Mode**: Observe and log without blocking — perfect for getting started
- **Multi-tenant**: Personal workspaces and team organizations
- **LLM Provider Agnostic**: Works with Anthropic Claude or OpenAI GPT
- **Framework Integrations**: LangChain, CrewAI, OpenAI Assistants
- **Tool Safety Catalog**: AI-powered safety grading (A-F)
- **Blast Radius Governor**: Rate and budget limits per agent
- **Deception Detection**: Catch goal drift and deceptive agent behavior
- **Honeypot Tripwires**: Decoy tools that detect unauthorized access
- **Config Export/Import**: Share rule packs between instances

## Quick Start

Choose your preferred deployment method:

### Docker (Recommended)

```bash
git clone https://github.com/snapwire-ai/snapwire.git
cd snapwire
cp .env.example .env
# Edit .env with your settings
docker-compose up -d
# Open http://localhost:5000
```

### Local Python

```bash
git clone https://github.com/snapwire-ai/snapwire.git
cd snapwire
pip install -e .
cp .env.example .env
# Edit .env with your settings  
python main.py
# Open http://localhost:5000
```

### Replit

Click the button below to deploy on Replit:

[![Deploy on Replit](https://replit.com/badge/github/snapwire-ai/snapwire)](https://replit.com/new/github/snapwire-ai/snapwire)

## Configuration

Create a `.env` file based on `.env.example` with the following key variables:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost/snapwire
# or use SQLite for local development
# DATABASE_URL=sqlite:///./snapwire.db

# LLM Provider
LLM_PROVIDER=anthropic  # or openai
ANTHROPIC_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here

# Session Secret (auto-generated if not set)
SESSION_SECRET=your-random-secret-here

# Server
PORT=5000
```

Refer to `.env.example` for all available configuration options.

## API Quick Start

Send tool calls to the intercept endpoint for real-time auditing:

```bash
curl -X POST https://your-server.com/api/intercept \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "send_email",
    "parameters": {"to": "user@example.com", "body": "Hello"},
    "agent_id": "my-agent"
  }'
```

The API returns an audit decision with metadata:

```json
{
  "allowed": true,
  "blocked": false,
  "audit_log_id": "audit_12345",
  "decision": "approved",
  "confidence": 0.98,
  "reasons": ["Tool usage within policy"]
}
```

## SDK

### Python SDK Example

```python
from agentic_firewall import FirewallClient

client = FirewallClient(api_key="your-api-key", base_url="http://localhost:5000")

# Intercept a tool call
response = client.intercept(
    tool_name="send_email",
    parameters={"to": "user@example.com", "body": "Hello"},
    agent_id="my-agent"
)

if response.allowed:
    print("Tool call approved")
else:
    print(f"Tool call blocked: {response.reasons}")
```

## Architecture

Snapwire is built with:

- **Backend**: Flask web framework with RESTful APIs
- **Database**: PostgreSQL (production) / SQLite (development)
- **LLM Auditor**: Integrates with Anthropic Claude or OpenAI GPT for intelligent auditing
- **Real-time Updates**: Server-Sent Events (SSE) for live audit log streaming
- **Multi-tenancy**: Isolated workspaces and organizations with role-based access control
- **Security**: API key authentication, encrypted credentials, audit logging

## Contributing

We welcome contributions! Here's how to get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes and commit: `git commit -am 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Submit a pull request

Please ensure:
- Code follows PEP 8 style guidelines
- New features include tests
- Documentation is updated
- Commit messages are clear and descriptive

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- Documentation: https://docs.snapwire.ai
- Issues: https://github.com/snapwire-ai/snapwire/issues
- Discussions: https://github.com/snapwire-ai/snapwire/discussions
