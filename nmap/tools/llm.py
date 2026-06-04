"""
llm.py
======
Provider-neutral LLM tool-calling layer for the AI Pentesting Assistant.

The agent loop should not care WHICH model vendor it talks to. This module hides
the differences behind one small interface so you can switch between:

    - anthropic   : Claude models, native Messages API + tool use
    - openai      : OpenAI models (chat.completions + function calling)
    - openrouter  : any model on OpenRouter (OpenAI-compatible endpoint)
    - gemini      : Google Gemini (OpenAI-compatible endpoint)

Design
------
Anthropic and the OpenAI-style vendors disagree on message shape and tool schema,
so we define ONE neutral representation and let each provider translate:

  * Neutral tool schema == our existing ``*_TOOL_SCHEMA`` dicts:
        {"name", "description", "input_schema": {...json schema...}}
  * Neutral conversation == a list of ``Turn`` objects (user / assistant / tool).
  * Every provider returns the same ``LLMReply`` (assistant text + tool calls).

The agent builds neutral turns, calls ``provider.chat(...)``, executes any tool
calls, appends neutral tool turns, and loops — identical code for every vendor.

Auth (env vars)
---------------
    anthropic   -> ANTHROPIC_API_KEY
    openai      -> OPENAI_API_KEY
    openrouter  -> OPENROUTER_API_KEY
    gemini      -> GEMINI_API_KEY  (or GOOGLE_API_KEY)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Neutral data types
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    """One tool invocation the model asked for."""
    id: str
    name: str
    input: dict


@dataclass
class Turn:
    """One neutral conversation turn.

    role == "user"      -> use `text`
    role == "assistant" -> may carry `text` and/or `tool_calls`
    role == "tool"      -> a tool result: `tool_call_id`, `name`, `text`
    """
    role: str
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str = ""
    name: str = ""


@dataclass
class LLMReply:
    """What every provider returns from one `chat` round."""
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = ""

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


# Known providers and their OpenAI-compatible base URLs / env keys.
# Anthropic is special-cased (native SDK), so it is not in this table.
_OPENAI_COMPAT = {
    "openai": {
        "base_url": None,  # SDK default
        "env": ["OPENAI_API_KEY"],
        "default_model": "gpt-4o",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "env": ["OPENROUTER_API_KEY"],
        "default_model": "openai/gpt-4o",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "env": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        "default_model": "gemini-2.0-flash",
    },
}

PROVIDERS = ["anthropic", *_OPENAI_COMPAT.keys()]

# Default model per provider when the caller doesn't pick one.
DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-8",
    **{k: v["default_model"] for k, v in _OPENAI_COMPAT.items()},
}


# ---------------------------------------------------------------------------
# Provider base
# ---------------------------------------------------------------------------

class LLMProvider:
    """Interface every provider implements."""

    name: str = "base"

    def chat(
        self,
        *,
        system: str,
        tools: list[dict],
        turns: list[Turn],
        max_tokens: int = 4096,
    ) -> LLMReply:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Anthropic (native Messages API)
# ---------------------------------------------------------------------------

class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, model: str, api_key: Optional[str] = None):
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise SystemExit(
                "The 'anthropic' package is required for the anthropic provider: "
                "pip install anthropic"
            ) from exc
        self.model = model
        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()

    @staticmethod
    def _tools(tools: list[dict]) -> list[dict]:
        # Our neutral schema already matches Anthropic's tool format.
        return tools

    @staticmethod
    def _messages(turns: list[Turn]) -> list[dict]:
        msgs: list[dict] = []
        for t in turns:
            if t.role == "user":
                msgs.append({"role": "user", "content": t.text})
            elif t.role == "assistant":
                content: list[dict] = []
                if t.text:
                    content.append({"type": "text", "text": t.text})
                for tc in t.tool_calls:
                    content.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.input,
                    })
                msgs.append({"role": "assistant", "content": content})
            elif t.role == "tool":
                msgs.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": t.tool_call_id,
                        "content": t.text,
                    }],
                })
        return msgs

    def chat(self, *, system, tools, turns, max_tokens=4096) -> LLMReply:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            tools=self._tools(tools),
            messages=self._messages(turns),
        )
        text_parts, calls = [], []
        for block in resp.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, input=block.input))
        return LLMReply(
            text="".join(text_parts).strip(),
            tool_calls=calls,
            stop_reason=resp.stop_reason or "",
        )


# ---------------------------------------------------------------------------
# OpenAI-compatible (openai / openrouter / gemini)
# ---------------------------------------------------------------------------

class OpenAICompatProvider(LLMProvider):
    """Talks to any OpenAI chat.completions-compatible endpoint."""

    def __init__(
        self,
        provider: str,
        model: str,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise SystemExit(
                "The 'openai' package is required for openai/openrouter/gemini: "
                "pip install openai"
            ) from exc
        self.name = provider
        self.model = model
        cfg = _OPENAI_COMPAT.get(provider, {})
        base_url = base_url or cfg.get("base_url")
        if api_key is None:
            for env in cfg.get("env", []):
                if os.environ.get(env):
                    api_key = os.environ[env]
                    break
        kwargs: dict[str, Any] = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        self._client = OpenAI(**kwargs)

    @staticmethod
    def _tools(tools: list[dict]) -> list[dict]:
        # Translate neutral schema -> OpenAI "function" tool format.
        return [{
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t["input_schema"],
            },
        } for t in tools]

    @staticmethod
    def _messages(system: str, turns: list[Turn]) -> list[dict]:
        msgs: list[dict] = [{"role": "system", "content": system}]
        for t in turns:
            if t.role == "user":
                msgs.append({"role": "user", "content": t.text})
            elif t.role == "assistant":
                m: dict[str, Any] = {"role": "assistant", "content": t.text or None}
                if t.tool_calls:
                    m["tool_calls"] = [{
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.input),
                        },
                    } for tc in t.tool_calls]
                msgs.append(m)
            elif t.role == "tool":
                msgs.append({
                    "role": "tool",
                    "tool_call_id": t.tool_call_id,
                    "name": t.name,
                    "content": t.text,
                })
        return msgs

    def chat(self, *, system, tools, turns, max_tokens=4096) -> LLMReply:
        resp = self._client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            tools=self._tools(tools),
            messages=self._messages(system, turns),
        )
        choice = resp.choices[0]
        msg = choice.message
        calls = []
        for tc in (msg.tool_calls or []):
            try:
                parsed = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                parsed = {}
            calls.append(ToolCall(id=tc.id, name=tc.function.name, input=parsed))
        return LLMReply(
            text=(msg.content or "").strip(),
            tool_calls=calls,
            stop_reason=choice.finish_reason or "",
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def make_provider(
    provider: str = "anthropic",
    model: Optional[str] = None,
    *,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> LLMProvider:
    """Build a provider by name.

    provider : one of PROVIDERS ("anthropic", "openai", "openrouter", "gemini").
    model    : model id; defaults to DEFAULT_MODELS[provider].
    api_key  : override; otherwise read from the provider's env var.
    base_url : override the endpoint (handy for self-hosted / proxies).
    """
    provider = provider.lower()
    model = model or DEFAULT_MODELS.get(provider)
    if provider == "anthropic":
        return AnthropicProvider(model=model, api_key=api_key)
    if provider in _OPENAI_COMPAT:
        return OpenAICompatProvider(
            provider=provider, model=model, api_key=api_key, base_url=base_url,
        )
    raise ValueError(f"Unknown provider {provider!r}. Choose from {PROVIDERS}.")


def env_key_for(provider: str) -> list[str]:
    """Return the env var name(s) that hold the API key for a provider."""
    if provider == "anthropic":
        return ["ANTHROPIC_API_KEY"]
    return list(_OPENAI_COMPAT.get(provider, {}).get("env", []))


def has_api_key(provider: str) -> bool:
    """True if at least one of the provider's env keys is set."""
    return any(os.environ.get(k) for k in env_key_for(provider))
