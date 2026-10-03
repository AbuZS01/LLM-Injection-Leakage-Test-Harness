import pytest

from harness.providers import get_provider


def test_openrouter_requires_key(monkeypatch):
    pytest.importorskip("openai")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
        get_provider("openrouter", "some/model")


def test_openrouter_requires_model(monkeypatch):
    pytest.importorskip("openai")
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    with pytest.raises(ValueError, match="--model"):
        get_provider("openrouter", None)


def test_openrouter_points_at_openrouter(monkeypatch):
    pytest.importorskip("openai")
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    p = get_provider("openrouter", "some/model")
    assert p.name == "openrouter"
    assert p.model == "some/model"
    assert "openrouter.ai/api/v1" in str(p.client.base_url)
