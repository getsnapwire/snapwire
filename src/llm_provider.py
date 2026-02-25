import os
import json
import logging

logger = logging.getLogger(__name__)

_client = None
_provider = None

SUPPORTED_PROVIDERS = ["anthropic", "openai"]


def _detect_provider():
    if os.environ.get("LLM_PROVIDER"):
        return os.environ["LLM_PROVIDER"].lower()
    if os.environ.get("AI_INTEGRATIONS_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    logger.info("No LLM provider configured. Defaulting to 'anthropic'. Set ANTHROPIC_API_KEY or OPENAI_API_KEY to enable AI features.")
    return "anthropic"


def _get_anthropic_key():
    return os.environ.get("AI_INTEGRATIONS_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")


def _get_anthropic_base_url():
    return os.environ.get("AI_INTEGRATIONS_ANTHROPIC_BASE_URL") or None


def get_provider():
    global _provider
    if _provider is None:
        _provider = _detect_provider()
    return _provider


def get_client():
    global _client
    if _client is not None:
        return _client

    provider = get_provider()

    if provider == "anthropic":
        key = _get_anthropic_key()
        if not key:
            logger.warning("No Anthropic API key found. Set ANTHROPIC_API_KEY in your environment variables. AI auditing features will not work until a key is configured.")
            return None
        from anthropic import Anthropic
        _client = Anthropic(
            api_key=key,
            base_url=_get_anthropic_base_url(),
        )
    elif provider == "openai":
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            logger.warning("No OpenAI API key found. Set OPENAI_API_KEY in your environment variables. AI auditing features will not work until a key is configured.")
            return None
        from openai import OpenAI
        _client = OpenAI(api_key=key)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}. Supported: {SUPPORTED_PROVIDERS}")

    return _client


def _get_tenant_llm_config(tenant_id):
    if not tenant_id:
        return None
    try:
        from models import TenantLLMConfig
        from src.llm_encryption import decrypt_api_key
        config = TenantLLMConfig.query.filter_by(tenant_id=tenant_id).first()
        if config:
            return {
                "provider": config.provider,
                "api_key": decrypt_api_key(config.encrypted_api_key),
            }
    except Exception as e:
        logger.warning(f"Failed to load tenant LLM config: {e}")
    return None


def _create_client_for_key(provider, api_key):
    if provider == "anthropic":
        from anthropic import Anthropic
        return Anthropic(api_key=api_key, base_url=_get_anthropic_base_url())
    elif provider == "openai":
        from openai import OpenAI
        return OpenAI(api_key=api_key)
    raise ValueError(f"Unsupported LLM provider: {provider}")


def chat(system_prompt, user_message, max_tokens=8192, model=None, tenant_id=None):
    tenant_config = _get_tenant_llm_config(tenant_id)

    if tenant_config:
        provider = tenant_config["provider"]
        client = _create_client_for_key(provider, tenant_config["api_key"])
    else:
        provider = get_provider()
        client = get_client()

    if client is None:
        raise RuntimeError(f"No API key configured for {provider}. Set {'ANTHROPIC_API_KEY' if provider == 'anthropic' else 'OPENAI_API_KEY'} in your environment variables, or add your key in Dashboard → Settings → LLM Provider.")

    if provider == "anthropic":
        if model is None:
            model = os.environ.get("LLM_MODEL", "claude-sonnet-4-5")
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return getattr(message.content[0], "text", "")

    elif provider == "openai":
        if model is None:
            model = os.environ.get("LLM_MODEL", "gpt-4o")
        response = client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        )
        return response.choices[0].message.content or ""

    raise ValueError(f"Unsupported LLM provider: {provider}")


def parse_json_response(response_text):
    try:
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(response_text[start:end])
        return json.loads(response_text)
    except json.JSONDecodeError:
        return None


def parse_json_array_response(response_text):
    try:
        start = response_text.find("[")
        end = response_text.rfind("]") + 1
        if start != -1 and end > start:
            return json.loads(response_text[start:end])
        return json.loads(response_text)
    except json.JSONDecodeError:
        return None


def get_provider_info(tenant_id=None):
    tenant_config = _get_tenant_llm_config(tenant_id)
    if tenant_config:
        return {
            "provider": tenant_config["provider"],
            "configured": True,
            "source": "tenant",
            "model": os.environ.get("LLM_MODEL", "claude-sonnet-4-5" if tenant_config["provider"] == "anthropic" else "gpt-4o"),
        }

    provider = get_provider()
    has_key = False
    if provider == "anthropic":
        has_key = bool(_get_anthropic_key())
    elif provider == "openai":
        has_key = bool(os.environ.get("OPENAI_API_KEY"))
    return {
        "provider": provider,
        "configured": has_key,
        "source": "environment",
        "model": os.environ.get("LLM_MODEL", "claude-sonnet-4-5" if provider == "anthropic" else "gpt-4o"),
    }
