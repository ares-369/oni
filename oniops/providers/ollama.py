"""Local Ollama provider (no API key, plain HTTP). The default."""

from __future__ import annotations

import re
from typing import Any

import requests

from .base import LLMProvider, LLMResult, Message

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, cfg: dict[str, Any], secret: str = ""):
        super().__init__(cfg, secret)
        self.base_url = (cfg.get("base_url") or "http://localhost:11434").rstrip("/")

    def chat(self, messages: list[Message], *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        use_model = model or self.default_model
        try:
            r = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": use_model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": temperature, "num_predict": max_tokens},
                },
                timeout=120,
            )
            r.raise_for_status()
            content = r.json().get("message", {}).get("content", "") or ""
            content = _THINK_RE.sub("", content).strip()
            return LLMResult(text=content or "(empty response)", model=use_model)
        except Exception as exc:
            return LLMResult(text="", model=use_model, error=f"Ollama error: {exc}")

    def available_models(self) -> list[str]:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=4)
            if r.status_code == 200:
                return [m["name"] for m in r.json().get("models", []) if "embed" not in m["name"]]
        except Exception:
            pass
        return super().available_models()

    def health(self) -> bool:
        try:
            return requests.get(f"{self.base_url}/api/tags", timeout=3).status_code == 200
        except Exception:
            return False
