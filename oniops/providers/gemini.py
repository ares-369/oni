"""Google Gemini provider. Needs GEMINI_API_KEY (Google AI Studio).

Note: a Google AI Pro subscription does NOT grant API access — a separate
AI Studio API key is required. SDK imported lazily.
"""

from __future__ import annotations

from typing import Any

from .base import LLMProvider, LLMResult, Message


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self, cfg: dict[str, Any], secret: str = ""):
        super().__init__(cfg, secret)
        self.default_model = cfg.get("default_model", "gemini-2.5-pro")

    def chat(self, messages: list[Message], *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        use_model = model or self.default_model
        if not self.secret:
            return LLMResult(text="", model=use_model, error="GEMINI_API_KEY not set")
        try:
            from google import genai  # lazy
            from google.genai import types

            client = genai.Client(api_key=self.secret)
            system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
            # Flatten the conversation into contents (role user/model).
            contents = []
            for m in messages:
                if m["role"] == "system":
                    continue
                role = "model" if m["role"] == "assistant" else "user"
                contents.append(types.Content(role=role, parts=[types.Part(text=m["content"])]))
            resp = client.models.generate_content(
                model=use_model,
                contents=contents,
                config=types.GenerateContentConfig(
                    system_instruction=system or None,
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                ),
            )
            return LLMResult(text=(resp.text or "").strip(), model=use_model)
        except Exception as exc:  # noqa: BLE001
            return LLMResult(text="", model=use_model, error=f"Gemini error: {exc}")

    def health(self) -> bool:
        return bool(self.secret)
