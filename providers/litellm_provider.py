import os
from typing import AsyncGenerator

import litellm
from litellm import acompletion

from .base import AIProvider, Message, ProviderConfig

litellm.suppress_debug_info = True


class LiteLLMProvider(AIProvider):
    def __init__(self, model_id: str, config: ProviderConfig):
        self._model_id = model_id
        self.config = config
        self._configure_env(model_id, config)

    def _configure_env(self, model_id: str, config: ProviderConfig):
        if config.api_key:
            if model_id.startswith("anthropic/") or "claude" in model_id:
                os.environ["ANTHROPIC_API_KEY"] = config.api_key
            elif model_id.startswith("openai/") or "gpt" in model_id or "o1" in model_id:
                os.environ["OPENAI_API_KEY"] = config.api_key
            elif model_id.startswith("gemini/"):
                os.environ["GEMINI_API_KEY"] = config.api_key
            elif model_id.startswith("mistral/"):
                os.environ["MISTRAL_API_KEY"] = config.api_key
            elif model_id.startswith("cohere/"):
                os.environ["COHERE_API_KEY"] = config.api_key
            elif model_id.startswith("groq/"):
                os.environ["GROQ_API_KEY"] = config.api_key
            elif model_id.startswith("together_ai/"):
                os.environ["TOGETHERAI_API_KEY"] = config.api_key
            elif model_id.startswith("perplexity/"):
                os.environ["PERPLEXITYAI_API_KEY"] = config.api_key
            elif model_id.startswith("azure/"):
                os.environ["AZURE_API_KEY"] = config.api_key
        if config.api_key and model_id.startswith("openrouter/"):
            os.environ["OPENROUTER_API_KEY"] = config.api_key
        if config.base_url and model_id.startswith("ollama/"):
            os.environ["OLLAMA_API_BASE"] = config.base_url

    @property
    def model_id(self) -> str:
        return self._model_id

    def _build_kwargs(self) -> dict:
        kwargs = {}
        if self._model_id.startswith("azure/") and self.config.extra.get("azure_api_base"):
            kwargs["api_base"] = self.config.extra["azure_api_base"]
            kwargs["api_version"] = self.config.extra.get("azure_api_version", "2024-02-01")
        if self._model_id.startswith("ollama/") and self.config.base_url:
            kwargs["api_base"] = self.config.base_url
        # custom openai-compatible provider
        if self._model_id.startswith("openai/") and self.config.base_url:
            kwargs["api_base"] = self.config.base_url
        return kwargs

    async def complete(self, messages: list[Message], temperature: float = 0.7, max_tokens: int = 4096) -> str:
        response = await acompletion(
            model=self._model_id,
            messages=[{"role": m.role, "content": m.content} for m in messages],
            temperature=temperature,
            max_tokens=max_tokens,
            **self._build_kwargs(),
        )
        return response.choices[0].message.content

    async def stream(self, messages: list[Message], temperature: float = 0.7, max_tokens: int = 4096) -> AsyncGenerator[str, None]:
        response = await acompletion(
            model=self._model_id,
            messages=[{"role": m.role, "content": m.content} for m in messages],
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            **self._build_kwargs(),
        )
        async for chunk in response:
            delta = chunk.choices[0].delta.content
            if delta:
                yield delta
