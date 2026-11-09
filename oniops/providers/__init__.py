"""Provider factory + role resolver.

``LLM.for_role("reporter")`` returns a (provider, model) bound pair the engine
can call without knowing or caring which backend serves it. Providers are
built lazily and cached; only the ones actually referenced get instantiated,
so an Ollama-only deployment never imports a cloud SDK.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import Config, get_config
from .base import LLMProvider, LLMResult, Message

# provider key in config -> (class path, env var holding its secret)
_SECRET_ENV = {
    "ollama": "",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "azure_openai": "AZURE_OPENAI_API_KEY",
    "openai_compatible": "OPENAI_COMPAT_API_KEY",
}


def _build(name: str, cfg: dict[str, Any], secret: str) -> LLMProvider:
    if name == "ollama":
        from .ollama import OllamaProvider
        return OllamaProvider(cfg, secret)
    if name == "anthropic":
        from .anthropic import AnthropicProvider
        return AnthropicProvider(cfg, secret)
    if name == "gemini":
        from .gemini import GeminiProvider
        return GeminiProvider(cfg, secret)
    if name in ("openai", "openai_compatible"):
        from .openai_compat import OpenAICompatProvider
        return OpenAICompatProvider(cfg, secret, name=name)
    if name == "azure_openai":
        from .openai_compat import OpenAICompatProvider
        return OpenAICompatProvider(cfg, secret, name="azure_openai", azure=True)
    raise ValueError(f"Unknown LLM provider: {name!r}")


@dataclass
class BoundModel:
    provider: LLMProvider
    model: str

    def chat(self, messages: list[Message], **kw) -> LLMResult:
        return self.provider.chat(messages, model=self.model, **kw)


class LLM:
    def __init__(self, cfg: Config | None = None):
        self.cfg = cfg or get_config()
        self._cache: dict[str, LLMProvider] = {}

    def provider(self, name: str) -> LLMProvider:
        if name not in self._cache:
            secret_env = _SECRET_ENV.get(name, "")
            secret = self.cfg.secret(secret_env) if secret_env else ""
            self._cache[name] = _build(name, self.cfg.provider_cfg(name), secret)
        return self._cache[name]

    def for_role(self, role: str) -> BoundModel:
        rc = self.cfg.role_cfg(role)
        pname = rc.get("provider", "ollama")
        prov = self.provider(pname)
        model = rc.get("model") or prov.default_model
        return BoundModel(provider=prov, model=model)

    def configured_providers(self) -> list[str]:
        provs = (self.cfg.llm.get("providers") or {}).keys()
        return list(provs)

    def health(self) -> dict[str, bool]:
        out: dict[str, bool] = {}
        for name in self.configured_providers():
            try:
                out[name] = self.provider(name).health()
            except Exception:
                out[name] = False
        return out


_LLM: LLM | None = None


def get_llm(reload: bool = False) -> LLM:
    global _LLM
    if _LLM is None or reload:
        _LLM = LLM()
    return _LLM
