from .base import AIProvider, Message, ProviderConfig
from .litellm_provider import LiteLLMProvider

PROVIDER_CATALOG = {
    # Anthropic
    "claude-sonnet-4-6": {"provider": "anthropic", "model": "claude-sonnet-4-6"},
    "claude-opus-4-8": {"provider": "anthropic", "model": "claude-opus-4-8"},
    "claude-haiku-4-5": {"provider": "anthropic", "model": "claude-haiku-4-5-20251001"},
    # OpenAI
    "gpt-4o": {"provider": "openai", "model": "gpt-4o"},
    "gpt-4o-mini": {"provider": "openai", "model": "gpt-4o-mini"},
    "o1": {"provider": "openai", "model": "o1"},
    # Google
    "gemini-1.5-pro": {"provider": "gemini", "model": "gemini/gemini-1.5-pro"},
    "gemini-2.0-flash": {"provider": "gemini", "model": "gemini/gemini-2.0-flash"},
    # Mistral
    "mistral-large": {"provider": "mistral", "model": "mistral/mistral-large-latest"},
    "mistral-medium": {"provider": "mistral", "model": "mistral/mistral-medium-latest"},
    # Cohere
    "command-r-plus": {"provider": "cohere", "model": "cohere/command-r-plus"},
    # Groq (fast inference)
    "groq-llama-70b": {"provider": "groq", "model": "groq/llama-3.3-70b-versatile"},
    "groq-mixtral": {"provider": "groq", "model": "groq/mixtral-8x7b-32768"},
    # Together AI
    "together-llama-70b": {"provider": "together_ai", "model": "together_ai/meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"},
    # Perplexity
    "perplexity-sonar": {"provider": "perplexity", "model": "perplexity/llama-3.1-sonar-large-128k-online"},
    # Azure OpenAI
    "azure-gpt-4o": {"provider": "azure", "model": "azure/gpt-4o"},
    # Ollama (local)
    "ollama-llama3": {"provider": "ollama", "model": "ollama/llama3.1"},
    "ollama-mistral": {"provider": "ollama", "model": "ollama/mistral"},
    "ollama-deepseek": {"provider": "ollama", "model": "ollama/deepseek-r1"},
    # OpenRouter (single key → 300+ models)
    "openrouter-claude-sonnet": {"provider": "openrouter", "model": "openrouter/anthropic/claude-sonnet-4-6"},
    "openrouter-gpt-4o": {"provider": "openrouter", "model": "openrouter/openai/gpt-4o"},
    "openrouter-gemini-pro": {"provider": "openrouter", "model": "openrouter/google/gemini-pro-1.5"},
    "openrouter-llama-70b": {"provider": "openrouter", "model": "openrouter/meta-llama/llama-3.1-70b-instruct"},
    "openrouter-deepseek-r1": {"provider": "openrouter", "model": "openrouter/deepseek/deepseek-r1"},
    "openrouter-qwen-72b": {"provider": "openrouter", "model": "openrouter/qwen/qwen-2.5-72b-instruct"},
    "openrouter-custom": {"provider": "openrouter", "model": "openrouter/"},
    # Custom OpenAI-compatible
    "custom": {"provider": "custom", "model": "openai/custom"},
}


def get_provider(model_id: str, config: "ProviderConfig") -> AIProvider:
    # Resolve catalog key → actual LiteLLM model string
    actual_model = PROVIDER_CATALOG.get(model_id, {}).get("model", model_id)
    return LiteLLMProvider(model_id=actual_model, config=config)
