"""
LLM provider abstraction for P4 Mini-CRS.
Supports: Ollama (on-prem), Claude (Anthropic API), OpenAI / any OpenAI-compatible endpoint.

Usage:
    provider = get_provider("ollama")
    provider = get_provider("claude", api_key="sk-ant-...")
    provider = get_provider("openai", api_key="sk-...", model="gpt-4o")
    provider = get_provider("openai-compat", endpoint="http://localhost:11434/v1", model="llama3")

    text = provider.generate("your prompt")
"""
from __future__ import annotations
import os
import json
import requests
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    name: str = "base"

    @abstractmethod
    def generate(self, prompt: str, timeout: int = 180) -> str:
        """Send prompt, return response text. Raises on hard failure."""

    @abstractmethod
    def is_available(self) -> bool:
        """Quick connectivity check."""

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model={getattr(self, 'model', '?')})"


# ── Ollama ────────────────────────────────────────────────────────────────────

class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, endpoint: str = "http://100.126.22.55:11434", model: str = "hermes3:70b"):
        self.endpoint = endpoint.rstrip("/")
        self.model = model

    def generate(self, prompt: str, timeout: int = 180) -> str:
        resp = requests.post(
            f"{self.endpoint}/api/generate",
            json={"model": self.model, "prompt": prompt, "stream": False},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json().get("response", "").strip()

    def is_available(self) -> bool:
        try:
            r = requests.get(f"{self.endpoint}/api/tags", timeout=5)
            return r.status_code == 200
        except Exception:
            return False


# ── Claude (Anthropic) ────────────────────────────────────────────────────────

class ClaudeProvider(LLMProvider):
    name = "claude"
    API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(
        self,
        api_key: str = "",
        model: str = "claude-sonnet-4-6",
        max_tokens: int = 4096,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self.max_tokens = max_tokens
        if not self.api_key:
            raise ValueError(
                "Claude provider requires api_key or ANTHROPIC_API_KEY env var."
            )

    def generate(self, prompt: str, timeout: int = 180) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = requests.post(self.API_URL, headers=headers, json=body, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"].strip()

    def is_available(self) -> bool:
        try:
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            # Minimal test call
            resp = requests.post(
                self.API_URL,
                headers=headers,
                json={"model": self.model, "max_tokens": 8,
                      "messages": [{"role": "user", "content": "hi"}]},
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            return False


# ── OpenAI / OpenAI-compatible ────────────────────────────────────────────────

class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(
        self,
        api_key: str = "",
        model: str = "gpt-4o",
        endpoint: str = "https://api.openai.com/v1",
        max_tokens: int = 4096,
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        self.max_tokens = max_tokens

    def generate(self, prompt: str, timeout: int = 180) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = requests.post(
            f"{self.endpoint}/chat/completions",
            headers=headers, json=body, timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    def is_available(self) -> bool:
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            r = requests.get(f"{self.endpoint}/models", headers=headers, timeout=5)
            return r.status_code == 200
        except Exception:
            return False


# ── Factory ───────────────────────────────────────────────────────────────────

def get_provider(
    provider: str,
    *,
    model: str = "",
    endpoint: str = "",
    api_key: str = "",
) -> LLMProvider:
    """
    Factory. provider: 'ollama' | 'claude' | 'openai' | 'openai-compat'

    openai-compat = any OpenAI-compatible API (Groq, Together, local vLLM, LM Studio, etc.)
    For Ollama via OpenAI-compat: endpoint=http://localhost:11434/v1, api_key=ollama
    """
    p = provider.lower().strip()

    if p == "ollama":
        return OllamaProvider(
            endpoint=endpoint or "http://100.126.22.55:11434",
            model=model or "hermes3:70b",
        )

    if p == "claude":
        return ClaudeProvider(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY", ""),
            model=model or "claude-sonnet-4-6",
        )

    if p in ("openai", "openai-compat"):
        default_endpoint = "https://api.openai.com/v1" if p == "openai" else endpoint
        if p == "openai-compat" and not default_endpoint:
            raise ValueError("openai-compat requires --llm-endpoint <url>")
        return OpenAIProvider(
            api_key=api_key or os.environ.get("OPENAI_API_KEY", ""),
            model=model or ("gpt-4o" if p == "openai" else ""),
            endpoint=default_endpoint,
        )

    raise ValueError(
        f"Unknown provider '{provider}'. Choose: ollama, claude, openai, openai-compat"
    )


def provider_from_args(args) -> LLMProvider | None:
    """Build provider from parsed CLI args. Returns None if --no-llm."""
    if getattr(args, "no_llm", False):
        return None
    return get_provider(
        getattr(args, "llm_provider", "ollama"),
        model=getattr(args, "llm_model", "") or "",
        endpoint=getattr(args, "llm_endpoint", "") or "",
        api_key=getattr(args, "llm_api_key", "") or "",
    )
