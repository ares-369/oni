"""Anthropic (Claude) provider. Needs ANTHROPIC_API_KEY. SDK imported lazily."""

from __future__ import annotations

from typing import Any

from .base import LLMProvider, LLMResult, Message


def _split_system(messages: list[Message]) -> tuple[str, list[Message]]:
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    convo = [m for m in messages if m["role"] != "system"]
    return system, convo


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, cfg: dict[str, Any], secret: str = ""):
        super().__init__(cfg, secret)
        self.default_model = cfg.get("default_model", "claude-sonnet-4-5")

    def _client(self):
        import anthropic  # lazy: only required if this provider is used
        return anthropic.Anthropic(api_key=self.secret)

    def chat(self, messages: list[Message], *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        use_model = model or self.default_model
        if not self.secret:
            return LLMResult(text="", model=use_model, error="ANTHROPIC_API_KEY not set")
        try:
            system, convo = _split_system(messages)
            resp = self._client().messages.create(
                model=use_model,
                system=system or None,
                messages=[{"role": m["role"], "content": m["content"]} for m in convo],
                temperature=temperature,
                max_tokens=max_tokens,
            )
            text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
            return LLMResult(text=text.strip(), model=use_model)
        except Exception as exc:  # noqa: BLE001
            return LLMResult(text="", model=use_model, error=f"Anthropic error: {exc}")

    def health(self) -> bool:
        return bool(self.secret)
