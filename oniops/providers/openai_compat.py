"""OpenAI and OpenAI-compatible providers.

One implementation covers:
  * openai            — api.openai.com (OPENAI_API_KEY)
  * azure_openai      — an Azure endpoint (AZURE_OPENAI_API_KEY + base_url)
  * openai_compatible — vLLM / LM Studio / OpenRouter / anything that speaks
                        the OpenAI Chat Completions API (OPENAI_COMPAT_API_KEY
                        + base_url)

The OpenAI Python SDK is imported lazily.
"""

from __future__ import annotations

from typing import Any

from .base import LLMProvider, LLMResult, Message


class OpenAICompatProvider(LLMProvider):
    name = "openai"

    def __init__(self, cfg: dict[str, Any], secret: str = "", *, name: str = "openai",
                 azure: bool = False):
        super().__init__(cfg, secret)
        self.name = name
        self.azure = azure
        self.base_url = cfg.get("base_url") or ""
        self.api_version = cfg.get("api_version", "2024-10-21")
        self.default_model = cfg.get("default_model", "gpt-4.1")

    def _client(self):
        if self.azure:
            from openai import AzureOpenAI  # lazy
            return AzureOpenAI(
                api_key=self.secret,
                azure_endpoint=self.base_url,
                api_version=self.api_version,
            )
        from openai import OpenAI  # lazy
        kwargs: dict[str, Any] = {"api_key": self.secret or "not-needed"}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return OpenAI(**kwargs)

    def chat(self, messages: list[Message], *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        use_model = model or self.default_model
        try:
            resp = self._client().chat.completions.create(
                model=use_model,
                messages=[{"role": m["role"], "content": m["content"]} for m in messages],
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return LLMResult(text=(resp.choices[0].message.content or "").strip(), model=use_model)
        except Exception as exc:
            return LLMResult(text="", model=use_model, error=f"{self.name} error: {exc}")

    def health(self) -> bool:
        # Local OpenAI-compatible servers may need no key; clouds do.
        return bool(self.secret or self.base_url)
