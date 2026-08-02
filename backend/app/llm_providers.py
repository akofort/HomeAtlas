"""Cloud/local LLM clients behind one interface, so the provider stays a user setting.

Provider-neutral on purpose: the whole point of the LLM settings page is that the household can
pick Claude, OpenAI, Gemini, DeepSeek, or a local Ollama box, so this talks raw HTTP via httpx
rather than pulling in one vendor's SDK. Structure follows GlucoSphere-Web's `llm_providers.py`
so both apps stay recognizably the same, with two corrections that matter on current models:

* **No sampling parameters are sent to Anthropic.** `temperature`/`top_p`/`top_k` were removed on
  Claude Opus 5, Sonnet 5, Opus 4.8 and 4.7 -- sending any of them is an HTTP 400, not a silently
  ignored field. Omitting them is valid on every Claude model, old and new, so they are simply
  never sent. (The other providers still get a low temperature; see `_TEMPERATURE`.)
* **`thinking` is never configured.** Claude's newer models think by default and the older ones
  don't; both are fine, and every explicit setting is wrong on some model in the range
  (`{"type": "disabled"}` 400s above `high` effort on Opus 5, `budget_tokens` 400s on 4.7+). The
  cost is that thinking shares the `max_tokens` budget, which is why `_MAX_TOKENS` is generous.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

import httpx

from . import model_catalog as catalog

_TIMEOUT = httpx.Timeout(120.0, connect=10.0)
# Low but non-zero for the providers that still accept it. This assistant reports facts about the
# household's own network -- invented IP addresses or invented device names would be worse than a
# dull answer. Anthropic gets no temperature at all (see module docstring).
_TEMPERATURE = 0.2
# Generous because on Claude's newer models thinking tokens come out of the same budget; a tight
# limit there truncates the answer mid-sentence rather than producing a shorter one.
_MAX_TOKENS = 8192


class ProviderError(RuntimeError):
    pass


@dataclass
class ChatResult:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    # Native tool calls, normalized across providers -- {"id": str, "name": str, "arguments": dict}.
    tool_calls: list[dict] | None = None
    # Verbatim provider payload for the assistant turn, keyed by provider. Anthropic requires
    # thinking blocks to be echoed back unchanged alongside tool_use blocks on the next turn, and
    # reconstructing them from `tool_calls` is not possible -- so the raw blocks ride along and
    # `tools.py` stores them on the message it appends to the history.
    provider_raw: dict = field(default_factory=dict)


_MODEL_SETTING_FIELD = {
    "CLAUDE": "claudeModel",
    "OPENAI": "openAiModel",
    "GEMINI": "geminiModel",
    "DEEPSEEK": "deepseekModel",
    "OLLAMA": "ollamaModel",
}
_KEY_SETTING_FIELD = {
    "CLAUDE": "claudeApiKey",
    "OPENAI": "openAiApiKey",
    "GEMINI": "geminiApiKey",
    "DEEPSEEK": "deepseekApiKey",
    "OLLAMA": "ollamaApiKey",
}
_BASE_URL_SETTING_FIELD = {
    "CLAUDE": ("claudeBaseUrl", catalog.DEFAULT_CLAUDE_BASE_URL),
    "OPENAI": ("openAiBaseUrl", catalog.DEFAULT_OPENAI_BASE_URL),
    "DEEPSEEK": ("deepseekBaseUrl", catalog.DEFAULT_DEEPSEEK_BASE_URL),
    "OLLAMA": ("ollamaBaseUrl", catalog.DEFAULT_OLLAMA_BASE_URL),
}


def live_models_for(provider_type: str, settings: dict) -> list[str] | None:
    cached = (settings.get("providerModelCache") or {}).get(provider_type) or {}
    ids = [m["id"] for m in cached.get("models") or [] if m.get("id")]
    return ids or None


def base_url_for(provider_type: str, settings: dict) -> str:
    field_name, default = _BASE_URL_SETTING_FIELD.get(provider_type, ("", ""))
    return (settings.get(field_name) or default).rstrip("/") if field_name else ""


def api_key_for(provider_type: str, settings: dict) -> str:
    return settings.get(_KEY_SETTING_FIELD.get(provider_type, ""), "") or ""


def resolved_model_for(provider_type: str, settings: dict, purpose: str = "CHAT") -> str:
    field_name = _MODEL_SETTING_FIELD.get(provider_type)
    if field_name is None:
        raise ProviderError(f"Unbekannter Anbieter: {provider_type}")
    return catalog.resolve(
        provider_type, settings.get(field_name, ""), purpose, live_models_for(provider_type, settings)
    )


# ---------------------------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------------------------

def _to_anthropic_tools(tools: list[dict]) -> list[dict]:
    return [
        {
            "name": t["name"],
            "description": t.get("description", ""),
            "input_schema": t.get("inputSchema") or {"type": "object", "properties": {}},
        }
        for t in tools
    ]


async def _chat_anthropic(api_key: str, base_url: str, model: str, system_prompt: str,
                          messages: list[dict], tools: list[dict] | None) -> ChatResult:
    url = f"{base_url.rstrip('/')}/messages"
    anthropic_messages: list[dict] = []
    for m in messages:
        if m.get("tool_calls"):
            raw = (m.get("providerRaw") or {}).get("anthropic")
            if raw:
                # Replay the assistant turn byte-for-byte. Thinking blocks carry a signature the
                # API validates, so anything reconstructed by hand is rejected.
                anthropic_messages.append({"role": "assistant", "content": raw})
            else:
                blocks: list[dict] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                blocks += [
                    {"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]}
                    for tc in m["tool_calls"]
                ]
                anthropic_messages.append({"role": "assistant", "content": blocks})
        elif m["role"] == "tool":
            anthropic_messages.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
            ]})
        else:
            anthropic_messages.append({"role": m["role"], "content": m["content"]})

    body: dict = {
        "model": model,
        "max_tokens": _MAX_TOKENS,
        "system": system_prompt,
        "messages": anthropic_messages,
    }
    if tools:
        body["tools"] = _to_anthropic_tools(tools)
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(url, json=body, headers=headers)
    if resp.status_code >= 400:
        raise ProviderError(f"Anthropic HTTP {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    blocks = data.get("content")
    if not isinstance(blocks, list):
        raise ProviderError("Anthropic: unerwartete Antwortstruktur (kein content-Array)")
    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    tool_calls = [
        {"id": b["id"], "name": b["name"], "arguments": b.get("input", {})}
        for b in blocks if b.get("type") == "tool_use"
    ]
    usage = data.get("usage", {})
    return ChatResult(
        text, data.get("model", model), usage.get("input_tokens"), usage.get("output_tokens"),
        tool_calls or None, {"anthropic": blocks} if tool_calls else {},
    )


# ---------------------------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------------------------

# Gemini's function-calling schema is a restricted subset of JSON Schema and rejects unrecognized
# keywords with a 400 covering the whole request. An allowlist of documented fields is the only
# approach that survives arbitrary tool schemas.
_GEMINI_SCHEMA_KEYS = {
    "type", "format", "description", "nullable", "enum", "items", "properties", "required",
    "minItems", "maxItems", "minLength", "maxLength", "pattern", "example", "anyOf",
}


def _sanitize_schema_for_gemini(schema: object) -> object:
    """`properties` and `items` are recursed into structurally -- filtering every dict's keys
    against the allowlist would also strip property *names*, since e.g. "host" is not a schema
    keyword."""
    if not isinstance(schema, dict):
        return schema
    result: dict[str, object] = {}
    for key, value in schema.items():
        if key == "properties" and isinstance(value, dict):
            result[key] = {k: _sanitize_schema_for_gemini(v) for k, v in value.items()}
        elif key == "items":
            result[key] = _sanitize_schema_for_gemini(value)
        elif key == "anyOf" and isinstance(value, list):
            result[key] = [_sanitize_schema_for_gemini(item) for item in value]
        elif key in _GEMINI_SCHEMA_KEYS:
            result[key] = value
    return result


async def _chat_gemini(api_key: str, model: str, system_prompt: str, messages: list[dict],
                       tools: list[dict] | None) -> ChatResult:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    contents = []
    for m in messages:
        role = "model" if m["role"] == "assistant" else "user"
        if m.get("tool_calls"):
            parts = []
            for tc in m["tool_calls"]:
                part: dict = {"functionCall": {"name": tc["name"], "args": tc["arguments"]}}
                # Gemini's thinking models reject a follow-up turn that drops the thoughtSignature
                # they emitted with their own functionCall.
                if tc.get("geminiThoughtSignature"):
                    part["thoughtSignature"] = tc["geminiThoughtSignature"]
                parts.append(part)
        elif m["role"] == "tool":
            parts = [{"functionResponse": {"name": m["name"], "response": {"result": m["content"]}}}]
            role = "user"
        else:
            parts = [{"text": m["content"]}]
        contents.append({"role": role, "parts": parts})

    body: dict = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": {"temperature": _TEMPERATURE},
    }
    if tools:
        body["tools"] = [{"functionDeclarations": [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": _sanitize_schema_for_gemini(t.get("inputSchema") or {"type": "object", "properties": {}}),
            }
            for t in tools
        ]}]
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(url, params={"key": api_key}, json=body)
    if resp.status_code >= 400:
        raise ProviderError(f"Gemini HTTP {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    try:
        parts = data["candidates"][0]["content"]["parts"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ProviderError(f"Gemini: unerwartete Antwortstruktur ({exc})") from exc
    text = "".join(p.get("text", "") for p in parts if "text" in p)
    tool_calls = []
    for p in parts:
        if "functionCall" not in p:
            continue
        call = {"id": p["functionCall"]["name"], "name": p["functionCall"]["name"],
                "arguments": p["functionCall"].get("args", {})}
        if p.get("thoughtSignature"):
            call["geminiThoughtSignature"] = p["thoughtSignature"]
        tool_calls.append(call)
    usage = data.get("usageMetadata", {})
    return ChatResult(text, model, usage.get("promptTokenCount"), usage.get("candidatesTokenCount"),
                      tool_calls or None)


# ---------------------------------------------------------------------------------------------
# OpenAI-compatible (OpenAI, DeepSeek, Ollama, OpenRouter, ...)
# ---------------------------------------------------------------------------------------------

def _json_loads(text: str) -> dict:
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


async def _chat_openai_compatible(api_key: str, base_url: str, model: str, system_prompt: str,
                                  messages: list[dict], tools: list[dict] | None) -> ChatResult:
    url = f"{base_url.rstrip('/')}/chat/completions"
    openai_messages: list[dict] = [{"role": "system", "content": system_prompt}]
    for m in messages:
        if m.get("tool_calls"):
            openai_messages.append({"role": "assistant", "content": m.get("content") or None, "tool_calls": [
                {"id": tc["id"], "type": "function",
                 "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"], ensure_ascii=False)}}
                for tc in m["tool_calls"]
            ]})
        elif m["role"] == "tool":
            openai_messages.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        else:
            openai_messages.append({"role": m["role"], "content": m["content"]})

    body: dict = {"model": model, "messages": openai_messages, "temperature": _TEMPERATURE}
    if tools:
        body["tools"] = [
            {"type": "function", "function": {
                "name": t["name"], "description": t.get("description", ""),
                "parameters": t.get("inputSchema") or {"type": "object", "properties": {}},
            }}
            for t in tools
        ]
    headers = {"content-type": "application/json"}
    if api_key:
        # Ollama needs no key; sending an empty bearer would be rejected by some proxies.
        headers["Authorization"] = f"Bearer {api_key}"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(url, json=body, headers=headers)
    if resp.status_code >= 400:
        raise ProviderError(f"HTTP {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    try:
        message = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ProviderError(f"Unerwartete Antwortstruktur ({exc})") from exc
    tool_calls = [
        {"id": tc.get("id") or tc["function"]["name"], "name": tc["function"]["name"],
         "arguments": _json_loads(tc["function"].get("arguments") or "{}")}
        for tc in (message.get("tool_calls") or [])
    ]
    usage = data.get("usage", {})
    return ChatResult(message.get("content") or "", data.get("model", model),
                      usage.get("prompt_tokens"), usage.get("completion_tokens"), tool_calls or None)


# ---------------------------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------------------------

async def chat(provider_type: str, settings: dict, system_prompt: str, messages: list[dict],
               purpose: str = "CHAT", tools: list[dict] | None = None) -> ChatResult:
    """`messages` is a list of turns, oldest first. Each is either
    `{"role": "user"|"assistant", "content": str}`, an assistant turn with
    `{"role": "assistant", "tool_calls": [...], "providerRaw": {...}}` (from a previous
    `ChatResult`), or a tool result `{"role": "tool", "tool_call_id": str, "name": str,
    "content": str}`."""
    model = resolved_model_for(provider_type, settings, purpose)
    if not model.strip():
        raise ProviderError("Kein Modell ausgewählt -- bitte unter Einstellungen -> KI-Assistent eines wählen.")
    key = api_key_for(provider_type, settings)
    if provider_type == "CLAUDE":
        return await _chat_anthropic(key, base_url_for(provider_type, settings), model, system_prompt, messages, tools)
    if provider_type == "GEMINI":
        return await _chat_gemini(key, model, system_prompt, messages, tools)
    if provider_type in catalog.OPENAI_COMPATIBLE:
        return await _chat_openai_compatible(key, base_url_for(provider_type, settings), model,
                                             system_prompt, messages, tools)
    raise ProviderError(f"Unbekannter Anbieter: {provider_type}")


# ---------------------------------------------------------------------------------------------
# Live model discovery + connection test
# ---------------------------------------------------------------------------------------------

async def refresh_models(provider_type: str, settings: dict) -> tuple[bool, str, list[dict]]:
    """Asks the provider which models this key may call. Returns (ok, message, models)."""
    key = api_key_for(provider_type, settings)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
            if provider_type == "GEMINI":
                resp = await client.get(
                    "https://generativelanguage.googleapis.com/v1beta/models", params={"key": key}
                )
            elif provider_type == "CLAUDE":
                resp = await client.get(
                    f"{base_url_for(provider_type, settings)}/models",
                    params={"limit": 100},
                    headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                )
            elif provider_type in catalog.OPENAI_COMPATIBLE:
                headers = {"Authorization": f"Bearer {key}"} if key else {}
                resp = await client.get(f"{base_url_for(provider_type, settings)}/models", headers=headers)
            else:
                return False, f"Unbekannter Anbieter: {provider_type}", []
    except httpx.HTTPError as exc:
        return False, f"Netzwerkfehler: {exc}", []

    if resp.status_code >= 400:
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}", []

    try:
        data = resp.json()
    except ValueError:
        return False, "Antwort war kein JSON -- stimmt die Server-Adresse?", []

    models: list[dict] = []
    if provider_type == "GEMINI":
        for entry in data.get("models") or []:
            methods = entry.get("supportedGenerationMethods") or []
            # Embedding and legacy models live in the same list but can't answer a chat request.
            if "generateContent" not in methods:
                continue
            model_id = (entry.get("name") or "").removeprefix("models/")
            if model_id:
                models.append({"id": model_id, "label": entry.get("displayName") or model_id})
    else:
        for entry in data.get("data") or []:
            model_id = entry.get("id")
            if model_id:
                models.append({"id": model_id, "label": entry.get("display_name") or model_id})

    if not models:
        return False, "Der Anbieter hat keine nutzbaren Modelle zurückgegeben.", []
    models.sort(key=lambda m: m["id"])
    return True, f"{len(models)} Modelle gefunden.", models


_MODEL_ERROR_CODES = ("model_not_found", "not_found_error", "invalid_model")
_MODEL_ERROR_PHRASES = ("not exist", "not found", "unknown", "invalid", "not a valid",
                        "not supported", "unsupported", "no endpoints")


def _describe_failure(error_text: str, model: str) -> str:
    """Turns a wall of provider JSON into a sentence about the actual problem. An invalid model id
    and an invalid API key otherwise look identical to a non-technical reader. The raw answer is
    always appended so a misclassification never hides what came back."""
    lowered = error_text.lower()
    mentions_model = "model" in lowered or (len(model) > 3 and model.lower() in lowered)
    if any(code in lowered for code in _MODEL_ERROR_CODES) or (
        mentions_model and any(phrase in lowered for phrase in _MODEL_ERROR_PHRASES)
    ):
        return f"Das Modell '{model}' gibt es bei diesem Anbieter nicht (oder der Zugang fehlt). Antwort: {error_text}"
    if "401" in lowered or "403" in lowered or "authent" in lowered or "api key" in lowered:
        return f"Der API-Schlüssel wurde abgelehnt. Antwort: {error_text}"
    return error_text


async def test_connection(provider_type: str, settings: dict) -> tuple[bool, str, str]:
    """A real one-shot completion against the model that would actually be used, so a manually
    entered model id is verified to exist AND be callable with this key -- not merely well-formed.
    Returns (ok, message, resolved_model)."""
    try:
        model = resolved_model_for(provider_type, settings)
    except ProviderError as exc:
        return False, str(exc), ""
    if not model.strip():
        return False, "Kein Modell angegeben -- bitte eines auswählen oder eine Modell-ID eintragen.", ""
    try:
        result = await chat(
            provider_type, settings,
            system_prompt="Antworte nur mit dem einzelnen Wort OK.",
            messages=[{"role": "user", "content": "Testverbindung -- antworte mit OK."}],
        )
    except ProviderError as exc:
        return False, _describe_failure(str(exc), model), model
    except httpx.HTTPError as exc:
        return False, f"Netzwerkfehler: {exc}", model
    reply = result.text.strip()
    if not reply:
        # Deliberately not a failure: saving is gated on a passing test, and some models return no
        # plain text for a trivial prompt. Hard-failing would lock the admin out of a working model.
        return True, f"Verbindung steht, aber '{model}' hat keinen Text geliefert -- bitte im Chat gegenprüfen.", model
    return True, reply[:200], model
