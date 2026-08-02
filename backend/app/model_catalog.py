"""Per-provider model catalogs and the "Automatisch" resolution rule.

The curated lists here are only a starting point -- provider line-ups move faster than this file,
so the LLM settings page offers a live refresh (see `llm_providers.refresh_models`) whose result
takes precedence. Ordering is load-bearing in both cases: first entry = fast/cheap, last entry =
flagship, which is what `resolve` uses to turn "Automatisch" into a concrete model id.
"""
from __future__ import annotations

from dataclasses import dataclass

AUTO_MODEL_ID = "auto"

DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_CLAUDE_BASE_URL = "https://api.anthropic.com/v1"
DEFAULT_DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"

PROVIDER_LABELS = {
    "CLAUDE": "Anthropic Claude API",
    "OPENAI": "OpenAI API / OpenRouter",
    "GEMINI": "Google Gemini API",
    "DEEPSEEK": "DeepSeek API (günstig)",
    "OLLAMA": "Ollama / lokaler Server (kostenlos, ohne Cloud)",
}


@dataclass(frozen=True)
class ModelOption:
    id: str
    label: str
    price_tier: str


_CLAUDE = [
    ModelOption("claude-haiku-4-5", "Claude Haiku 4.5 (schnell, günstig)", "€"),
    ModelOption("claude-sonnet-5", "Claude Sonnet 5 (Allrounder)", "€€"),
    ModelOption("claude-opus-5", "Claude Opus 5 (Tiefenanalyse)", "€€€"),
]
_OPENAI = [
    ModelOption("gpt-4o-mini", "GPT-4o mini (schnell, günstig)", "€"),
    ModelOption("gpt-4o", "GPT-4o (Allrounder)", "€€"),
]
_GEMINI = [
    ModelOption("gemini-2.0-flash", "Gemini 2.0 Flash (schnell)", "€"),
    ModelOption("gemini-2.5-pro", "Gemini 2.5 Pro (Tiefenanalyse)", "€€"),
]
_DEEPSEEK = [
    ModelOption("deepseek-chat", "DeepSeek Chat (schnell, empfohlen)", "€"),
    ModelOption("deepseek-reasoner", "DeepSeek Reasoner (Tiefenanalyse)", "€€"),
]
# Deliberately empty: an Ollama server hosts whatever the user pulled, so a curated list would be
# wrong for everyone. The live refresh fills the picker from /v1/models.
_OLLAMA: list[ModelOption] = []

_CATALOG: dict[str, list[ModelOption]] = {
    "CLAUDE": _CLAUDE,
    "OPENAI": _OPENAI,
    "GEMINI": _GEMINI,
    "DEEPSEEK": _DEEPSEEK,
    "OLLAMA": _OLLAMA,
}

# Providers whose wire format is OpenAI's /chat/completions.
OPENAI_COMPATIBLE = ("OPENAI", "DEEPSEEK", "OLLAMA")


def options_for(provider_type: str) -> list[ModelOption]:
    return _CATALOG.get(provider_type, [])


def is_known_model(provider_type: str, model_id: str) -> bool:
    return any(m.id == model_id for m in options_for(provider_type))


def resolve(provider_type: str, selection: str, purpose: str = "CHAT", live_models: list[str] | None = None) -> str:
    """`purpose` is "CHAT" (fast, used for the assistant and device classification) or "ANALYSIS"
    (flagship, used when writing the documentation).

    `live_models` are ids from a live refresh. They constrain the answer to what the account can
    actually call, but they arrive in whatever order the provider returned -- which is *not* the
    fast-to-flagship ordering the curated catalog guarantees. So the curated pick wins whenever the
    live list confirms it exists, and only otherwise does position decide. Picking `live[0]` blindly
    would resolve "Automatisch" to whatever happens to sort first at the provider, which for
    OpenRouter-style endpoints is essentially arbitrary."""
    if selection and selection != AUTO_MODEL_ID:
        return selection
    curated = [m.id for m in options_for(provider_type)]
    preferred = (curated[0] if purpose == "CHAT" else curated[-1]) if curated else ""
    if live_models:
        if preferred in live_models:
            return preferred
        return live_models[0] if purpose == "CHAT" else live_models[-1]
    return preferred or selection or ""
