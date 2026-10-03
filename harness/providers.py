"""Model providers. Each exposes complete(system, user) -> Completion.

The mock providers need no API key. They exist to test the harness itself
(detectors, scoring, reporting) in CI, not to say anything about real models.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Completion:
    text: str
    refused: bool = False
    stop_reason: str | None = None


class Provider:
    name = "base"

    def __init__(self, model: str | None = None):
        self.model = model or "n/a"

    def complete(self, system: str, user: str) -> Completion:
        raise NotImplementedError


class MockEcho(Provider):
    """Worst-case target: repeats its whole context. Every secret it holds leaks."""

    name = "mock-echo"

    def complete(self, system: str, user: str) -> Completion:
        return Completion(text=f"{system}\n\n{user}", stop_reason="end_turn")


class MockRefuse(Provider):
    """Best-case-for-security, useless-for-business target: never says anything."""

    name = "mock-refuse"

    def complete(self, system: str, user: str) -> Completion:
        return Completion(text="I can't help with that.", stop_reason="end_turn")


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, model: str | None = None, effort: str | None = None):
        import anthropic

        super().__init__(model or "claude-opus-5-5")
        self._anthropic = anthropic
        self.client = anthropic.Anthropic(max_retries=4)
        self.effort = effort

    def complete(self, system: str, user: str) -> Completion:
        # No server-side refusal fallbacks on purpose: a fallback would answer
        # the attack with a different model and contaminate the measurement.
        kwargs = {}
        if self.effort:
            kwargs["output_config"] = {"effort": self.effort}
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=8000,
            system=system,
            messages=[{"role": "user", "content": user}],
            **kwargs,
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        return Completion(text=text, refused=resp.stop_reason == "refusal", stop_reason=resp.stop_reason)


class OpenAICompatibleProvider(Provider):
    """Any OpenAI-compatible chat completions API (OpenAI, Gemini's compat endpoint, OpenRouter, Groq...)."""

    name = "openai-compatible"

    def __init__(self, model: str | None = None, base_url: str | None = None, api_key: str | None = None):
        if not model:
            raise ValueError(f"--model is required for the {self.name} provider")
        from openai import OpenAI

        super().__init__(model)
        self.client = OpenAI(base_url=base_url or os.environ.get("OPENAI_BASE_URL"), api_key=api_key, max_retries=4)

    def complete(self, system: str, user: str) -> Completion:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        choice = resp.choices[0]
        refusal = getattr(choice.message, "refusal", None)
        return Completion(
            text=choice.message.content or refusal or "",
            refused=bool(refusal) or choice.finish_reason == "content_filter",
            stop_reason=choice.finish_reason,
        )


class OpenRouterProvider(OpenAICompatibleProvider):
    """OpenRouter: one key, many models. Model IDs look like 'vendor/model' (see openrouter.ai/models)."""

    name = "openrouter"
    BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self, model: str | None = None):
        key = os.environ.get("OPENROUTER_API_KEY")
        if not key:
            raise ValueError("Set OPENROUTER_API_KEY to use the openrouter provider")
        super().__init__(model, base_url=self.BASE_URL, api_key=key)


def get_provider(name: str, model: str | None = None, base_url: str | None = None, effort: str | None = None) -> Provider:
    if name == "mock-echo":
        return MockEcho(model)
    if name == "mock-refuse":
        return MockRefuse(model)
    if name == "anthropic":
        return AnthropicProvider(model, effort=effort)
    if name == "openai-compatible":
        return OpenAICompatibleProvider(model, base_url=base_url)
    if name == "openrouter":
        return OpenRouterProvider(model)
    raise ValueError(f"Unknown provider {name!r}")
