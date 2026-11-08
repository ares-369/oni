"""Common LLM provider interface.

Every provider implements the same surface so the engine never cares which
model is behind a role. Tool-calling (``chat_with_tools``) is defined here and
used by the Phase 3 agent loop; providers that lack native tool use fall back
to a ReAct-style prompt.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

Message = dict[str, str]  # {"role": "system|user|assistant", "content": "..."}


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResult:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    model: str = ""
    error: str | None = None


class LLMProvider(ABC):
    name: str = "base"

    def __init__(self, cfg: dict[str, Any], secret: str = ""):
        self.cfg = cfg or {}
        self.secret = secret
        self.default_model = self.cfg.get("default_model", "")

    @abstractmethod
    def chat(
        self,
        messages: list[Message],
        *,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 900,
    ) -> LLMResult:
        ...

    def chat_with_tools(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]],
        *,
        model: str | None = None,
    ) -> LLMResult:
        # Default: providers without native tool use just answer in text.
        # The agent loop (Phase 3) handles ReAct parsing for these.
        return self.chat(messages, model=model)

    def available_models(self) -> list[str]:
        return [self.default_model] if self.default_model else []

    def health(self) -> bool:
        return True
