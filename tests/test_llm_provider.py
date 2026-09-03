"""Tests for LLM provider factory and individual providers."""
from __future__ import annotations
from unittest.mock import MagicMock, patch

import pytest

from engine.llm_provider import (
    ClaudeProvider,
    OllamaProvider,
    OpenAIProvider,
    get_provider,
    provider_from_args,
)


# ── Factory ───────────────────────────────────────────────────────────────────

def test_get_provider_ollama():
    p = get_provider("ollama")
    assert isinstance(p, OllamaProvider)


def test_get_provider_claude():
    p = get_provider("claude", api_key="test-key")
    assert isinstance(p, ClaudeProvider)
    assert p.api_key == "test-key"


def test_get_provider_openai():
    p = get_provider("openai")
    assert isinstance(p, OpenAIProvider)
    assert "openai.com" in p.endpoint


def test_get_provider_openai_compat():
    p = get_provider("openai-compat", endpoint="http://localhost:11434/v1")
    assert isinstance(p, OpenAIProvider)
    assert p.endpoint == "http://localhost:11434/v1"


def test_get_provider_openai_compat_no_endpoint_raises():
    with pytest.raises(ValueError, match="openai-compat requires"):
        get_provider("openai-compat")


def test_get_provider_unknown_raises():
    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider("llamafile")


def test_get_provider_case_insensitive():
    p = get_provider("OLLAMA")
    assert isinstance(p, OllamaProvider)


# ── OllamaProvider ────────────────────────────────────────────────────────────

@patch("engine.llm_provider.requests.post")
def test_ollama_generate_returns_response(mock_post):
    mock_post.return_value.raise_for_status = MagicMock()
    mock_post.return_value.json.return_value = {"response": "  CWE-122 found  "}

    p = OllamaProvider(endpoint="http://localhost:11434")
    result = p.generate("analyze this crash")

    assert result == "CWE-122 found"
    mock_post.assert_called_once()
    call_json = mock_post.call_args.kwargs["json"]
    assert call_json["prompt"] == "analyze this crash"


@patch("engine.llm_provider.requests.post")
def test_ollama_generate_raises_on_http_error(mock_post):
    import requests
    mock_post.return_value.raise_for_status.side_effect = requests.HTTPError("500")

    p = OllamaProvider()
    with pytest.raises(requests.HTTPError):
        p.generate("prompt")


@patch("engine.llm_provider.requests.get")
def test_ollama_is_available_true(mock_get):
    mock_get.return_value.status_code = 200
    p = OllamaProvider()
    assert p.is_available() is True


@patch("engine.llm_provider.requests.get")
def test_ollama_is_available_false_on_exception(mock_get):
    mock_get.side_effect = ConnectionError()
    p = OllamaProvider()
    assert p.is_available() is False


# ── ClaudeProvider ────────────────────────────────────────────────────────────

def test_claude_provider_no_api_key_raises():
    with pytest.raises(ValueError, match="api_key"):
        ClaudeProvider(api_key="")


@patch("engine.llm_provider.requests.post")
def test_claude_generate_returns_text(mock_post):
    mock_post.return_value.raise_for_status = MagicMock()
    mock_post.return_value.json.return_value = {
        "content": [{"text": "  heap overflow at line 22  "}]
    }

    p = ClaudeProvider(api_key="sk-ant-test")
    result = p.generate("analyze crash")

    assert result == "heap overflow at line 22"
    headers = mock_post.call_args.kwargs["headers"]
    assert headers["x-api-key"] == "sk-ant-test"


@patch("engine.llm_provider.requests.post")
def test_claude_generate_raises_on_http_error(mock_post):
    import requests
    mock_post.return_value.raise_for_status.side_effect = requests.HTTPError("401")

    p = ClaudeProvider(api_key="bad-key")
    with pytest.raises(requests.HTTPError):
        p.generate("prompt")


# ── OpenAIProvider ────────────────────────────────────────────────────────────

@patch("engine.llm_provider.requests.post")
def test_openai_generate_returns_content(mock_post):
    mock_post.return_value.raise_for_status = MagicMock()
    mock_post.return_value.json.return_value = {
        "choices": [{"message": {"content": "  CWE-134 format string  "}}]
    }

    p = OpenAIProvider(api_key="sk-test", model="gpt-4o")
    result = p.generate("analyze")

    assert result == "CWE-134 format string"


@patch("engine.llm_provider.requests.get")
def test_openai_is_available_true(mock_get):
    mock_get.return_value.status_code = 200
    p = OpenAIProvider(api_key="sk-test")
    assert p.is_available() is True


@patch("engine.llm_provider.requests.get")
def test_openai_is_available_false(mock_get):
    mock_get.side_effect = ConnectionError()
    p = OpenAIProvider(api_key="sk-test")
    assert p.is_available() is False


# ── provider_from_args ────────────────────────────────────────────────────────

def test_provider_from_args_no_llm_returns_none():
    args = MagicMock()
    args.no_llm = True
    assert provider_from_args(args) is None


def test_provider_from_args_ollama():
    args = MagicMock()
    args.no_llm = False
    args.llm_provider = "ollama"
    args.llm_model = ""
    args.llm_endpoint = ""
    args.llm_api_key = ""
    p = provider_from_args(args)
    assert isinstance(p, OllamaProvider)
