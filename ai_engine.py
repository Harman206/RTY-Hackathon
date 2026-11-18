"""AI compliance engine: regulation-vs-company-state gap analysis and audit-log generation.

Public contract (imported by the API layer):

    from ai_engine import analyze_compliance_gap, generate_audit_trail, LLMError

All functions are synchronous and return plain JSON-serializable Python objects.
Bring your own key: every public function takes an optional keyword-only `api_key`, so
each end user can run the engine on their own Anthropic API key. When `api_key` is not
given, ANTHROPIC_API_KEY from the environment is used. Keys are never logged or stored
beyond the in-memory SDK client cache.

Configuration is read from the environment at call time, never at import time:

    ANTHROPIC_API_KEY     required unless the caller passes api_key=
    LLM_MODEL             optional, default "claude-sonnet-5-5"
    LLM_TIMEOUT_SECONDS   optional, default 60
    LLM_EFFORT            optional (low | medium | high | xhigh | max), default "medium"
"""

from __future__ import annotations

import difflib
import hashlib
import json
import logging
import os
import re
import threading
import unicodedata
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Literal

import anthropic
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from prompts import (
    ANALYSIS_SCHEMA,
    ANALYSIS_SYSTEM_PROMPT,
    ANOMALY_ITEM_FIELDS,
    AUDIT_SYSTEM_PROMPT,
    MAX_ANOMALIES,
    build_analysis_prompt,
    build_audit_prompt,
)

__all__ = [
    "LLMError",
    "LLMConfigError",
    "LLMOutputError",
    "call_llm",
    "analyze_compliance_gap",
    "generate_audit_trail",
]

logger = logging.getLogger("ai_engine")

DEFAULT_MODEL = "claude-sonnet-5-5"
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_EFFORT = "medium"
VALID_EFFORTS = ("low", "medium", "high", "xhigh", "max")
SDK_MAX_RETRIES = 3
MAX_ATTEMPTS = 3  # total attempts on unusable output
AUDIT_ATTEMPTS = 2  # LLM attempts for the audit log before the deterministic fallback
DEFAULT_MAX_TOKENS = 16000  # room for adaptive thinking plus up to 25 findings

MAX_REGULATION_CHARS = 100_000
MAX_STATE_CHARS = 20_000
MAX_TITLE_CHARS = 80
MAX_EXCERPT_CHARS = 200
NOT_SPECIFIED = "Not specified in company state"

# Server-side refusal fallback: if the model declines, the API re-runs the request on
# a fallback model inside the same call.
_FALLBACK_BETA = "server-side-fallback-2026-07-01"

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
OUTPUT_KEYS = ("id",) + ANOMALY_ITEM_FIELDS


# --------------------------------------------------------------------------- errors


class LLMError(RuntimeError):
    """Base class for every failure of the LLM layer."""


class LLMConfigError(LLMError):
    """Missing API key or bad configuration."""


class LLMOutputError(LLMError):
    """The model's output was unusable after all retries."""


# --------------------------------------------------------------------------- config


def _model_name() -> str:
    return os.environ.get("LLM_MODEL", "").strip() or DEFAULT_MODEL


def _timeout_seconds() -> float:
    raw = os.environ.get("LLM_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        raise LLMConfigError("LLM_TIMEOUT_SECONDS must be a number") from None
    if value <= 0:
        raise LLMConfigError("LLM_TIMEOUT_SECONDS must be positive")
    return value


def _effort() -> str:
    raw = os.environ.get("LLM_EFFORT", "").strip().lower() or DEFAULT_EFFORT
    if raw not in VALID_EFFORTS:
        raise LLMConfigError(f"LLM_EFFORT must be one of {', '.join(VALID_EFFORTS)}")
    return raw


# --------------------------------------------------------------------------- client

_MAX_CACHED_CLIENTS = 64
_clients: OrderedDict[tuple[str, float], anthropic.Anthropic] = OrderedDict()
_client_lock = threading.Lock()


def _check_api_key(api_key: Any) -> None:
    """Reject a malformed caller-supplied key before any work is done."""
    if api_key is not None and (not isinstance(api_key, str) or not api_key.strip()):
        raise ValueError("api_key must be a non-empty string or None")


def _get_client(api_key: str | None = None) -> anthropic.Anthropic:
    """Lazy, cached SDK client for the caller's key (or ANTHROPIC_API_KEY).

    The key is read at call time, never at import time. One client is kept per
    (key, timeout), keyed by a hash so plaintext keys are not used as dict keys;
    the least recently used client is dropped beyond _MAX_CACHED_CLIENTS.
    """
    key = (api_key if api_key is not None else os.environ.get("ANTHROPIC_API_KEY", "")).strip()
    if not key:
        raise LLMConfigError("no API key: pass api_key= or set ANTHROPIC_API_KEY")
    timeout = _timeout_seconds()
    cache_key = (hashlib.sha256(key.encode()).hexdigest(), timeout)
    with _client_lock:
        client = _clients.get(cache_key)
        if client is None:
            client = anthropic.Anthropic(api_key=key, timeout=timeout, max_retries=SDK_MAX_RETRIES)
            _clients[cache_key] = client
            while len(_clients) > _MAX_CACHED_CLIENTS:
                _clients.popitem(last=False)
        else:
            _clients.move_to_end(cache_key)
        return client


def _provider_complete(
    prompt: str,
    system_message: str,
    json_mode: bool,
    schema: dict | None,
    temperature: float,
    max_tokens: int,
    *,
    api_key: str | None = None,
) -> dict | str:
    """The only function that touches the provider SDK. Swap this to change provider.

    Returns the raw text of the response (a JSON string in JSON mode). `temperature` is
    accepted for interface compatibility but not sent: current Claude models reject
    sampling parameters, and structured outputs already constrain the JSON shape.
    """
    client = _get_client(api_key)
    system = system_message
    output_config: dict[str, Any] = {"effort": _effort()}
    if json_mode:
        if schema:
            output_config["format"] = {"type": "json_schema", "schema": schema}
        else:
            system = (system + "\n\n" if system else "") + (
                "Respond with a single JSON object only: no prose, no markdown fences."
            )
    kwargs: dict[str, Any] = {
        "model": _model_name(),
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
        "output_config": output_config,
        "betas": [_FALLBACK_BETA],
        "fallbacks": "default",
    }
    if system:
        kwargs["system"] = system

    try:
        # Streaming keeps long generations inside the per-read timeout.
        with client.beta.messages.stream(**kwargs) as stream:
            message = stream.get_final_message()
    except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
        raise LLMConfigError(f"the API key was rejected by the provider ({type(exc).__name__})") from exc
    except anthropic.NotFoundError as exc:
        raise LLMConfigError(f"model '{_model_name()}' not found") from exc
    except anthropic.APIStatusError as exc:
        raise LLMError(f"provider error: HTTP {exc.status_code} ({type(exc).__name__})") from exc
    except anthropic.AnthropicError as exc:
        raise LLMError(f"provider error: {type(exc).__name__}") from exc

    if message.stop_reason == "refusal":
        raise LLMOutputError("model declined the request")
    if message.stop_reason == "max_tokens":
        raise LLMOutputError("model output was truncated at max_tokens")
    text = "".join(
        getattr(block, "text", "") for block in message.content if block.type == "text"
    )
    if not text.strip():
        raise LLMOutputError("model returned no text")
    return text


# --------------------------------------------------------------------------- JSON hardening

_FENCE_RE = re.compile(r"^```[a-zA-Z0-9_-]*\s*\n?(.*?)\n?\s*```$", re.DOTALL)


def _strip_fences(text: str) -> str:
    match = _FENCE_RE.match(text.strip())
    return match.group(1).strip() if match else text.strip()


def _coerce_json_object(raw: Any) -> dict:
    """Turn a model response into a dict, repairing common formatting damage."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        raise LLMOutputError(f"expected a JSON object, got {type(raw).__name__}")

    text = _strip_fences(raw.strip().lstrip("﻿").strip())
    value: Any = None
    try:
        value = json.loads(text)
        if isinstance(value, str):  # double-encoded JSON
            value = json.loads(value.strip())
    except (json.JSONDecodeError, ValueError):
        value = None
    if not isinstance(value, dict):
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                value = json.loads(text[start : end + 1])
            except (json.JSONDecodeError, ValueError):
                value = None
    if not isinstance(value, dict):
        raise LLMOutputError("model output is not a JSON object")
    return value


# --------------------------------------------------------------------------- call_llm


def call_llm(
    prompt: str,
    system_message: str = "",
    json_mode: bool = True,
    *,
    schema: dict | None = None,
    temperature: float = 0.0,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    api_key: str | None = None,
) -> dict | str:
    """Send one prompt to the LLM. JSON mode returns a dict; text mode returns a str.

    `api_key` overrides ANTHROPIC_API_KEY for this call (bring your own key).
    """
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    if not isinstance(system_message, str):
        raise ValueError("system_message must be a string")
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
        raise ValueError("max_tokens must be a positive integer")
    _check_api_key(api_key)

    last_error: LLMOutputError | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            raw = _provider_complete(
                prompt, system_message, json_mode, schema, temperature, max_tokens,
                api_key=api_key,
            )
            if json_mode:
                return _coerce_json_object(raw)
            if not isinstance(raw, str):
                raise LLMOutputError(f"expected text, got {type(raw).__name__}")
            return raw
        except LLMOutputError as exc:
            last_error = exc
            logger.warning("call_llm attempt %d/%d: unusable output (%s)", attempt, MAX_ATTEMPTS, exc)
        except LLMError:
            raise
        except Exception as exc:  # never let an unexpected type escape
            logger.error("call_llm attempt %d: unexpected %s", attempt, type(exc).__name__)
            raise LLMError(f"unexpected error: {type(exc).__name__}") from exc
    raise LLMOutputError(f"unusable output after {MAX_ATTEMPTS} attempts: {last_error}")


# --------------------------------------------------------------------------- analysis


class _Anomaly(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    title: str
    category: Literal[
        "data_retention", "access_control", "security", "privacy_consent",
        "reporting", "governance", "other",
    ]
    severity: Literal["low", "medium", "high", "critical"]
    gap_type: Literal["non_compliant", "insufficient_information"]
    regulation_requirement: str
    regulation_excerpt: str
    current_state: str
    gap_description: str
    recommended_remediation: str

    @field_validator("category", "severity", "gap_type", mode="before")
    @classmethod
    def _normalize_enum(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().lower().replace("-", "_").replace(" ", "_")
        return value

    @field_validator("title", "gap_description", "regulation_requirement", "recommended_remediation")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must not be empty")
        return value


class _AnalysisPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    anomalies: list[_Anomaly]


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    cut = text[: limit - 1].rstrip()
    space = cut.rfind(" ")
    if space > limit // 2:
        cut = cut[:space].rstrip()
    return cut + "…"


def _truncate_verbatim(text: str, limit: int) -> str:
    """Shorten a quote by cutting it, never adding characters, so it stays verbatim."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    space = cut.rfind(" ")
    if space > limit // 2:
        cut = cut[:space]
    return cut.rstrip(" ,;:")


_QUOTE_MAP = str.maketrans({
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "–": "-", "—": "-", " ": " ",
})


def _normalized_with_map(text: str) -> tuple[str, list[int]]:
    """Casefold, unify quotes/dashes, collapse whitespace; map each char back to the source."""
    out: list[str] = []
    index: list[int] = []
    prev_space = True
    for i, ch in enumerate(text):
        ch = unicodedata.normalize("NFKC", ch).translate(_QUOTE_MAP).casefold()
        for c in ch:
            if c.isspace():
                if prev_space:
                    continue
                c, prev_space = " ", True
            else:
                prev_space = False
            out.append(c)
            index.append(i)
    return "".join(out), index


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.;!?])\s+(?=[A-Z0-9(\"'])|\n+")
_WORD_RE = re.compile(r"[a-z0-9]{3,}")


def _source_slice(regulation: str, index: list[int], start: int, length: int) -> str:
    end = index[min(start + length, len(index)) - 1] + 1
    return regulation[index[start] : end]


def _ground_excerpt(excerpt: str, regulation: str, norm_reg: str, index: list[int]) -> str:
    """Return a verbatim quote from the regulation that supports the finding.

    The model's excerpt is located in the regulation (ignoring case, whitespace and quote
    style) and replaced with the exact source text. If it cannot be found, the closest
    regulation sentence is used instead, so every excerpt is a real quote.
    """
    norm_ex = _normalized_with_map(excerpt)[0].strip().strip("\"'…. ")
    if norm_ex:
        pos = norm_reg.find(norm_ex)
        if pos != -1:
            return _truncate_verbatim(_source_slice(regulation, index, pos, len(norm_ex)).strip(), MAX_EXCERPT_CHARS)
        # The model sometimes joins two fragments with "..."; ground the longest fragment.
        fragments = sorted((f.strip() for f in re.split(r"\.{3}|…", norm_ex)), key=len, reverse=True)
        for frag in fragments:
            if len(frag) >= 20:
                pos = norm_reg.find(frag)
                if pos != -1:
                    return _truncate_verbatim(_source_slice(regulation, index, pos, len(frag)).strip(), MAX_EXCERPT_CHARS)

    # Not quoted verbatim: use the regulation sentence that shares the most words with it.
    sentences = [s.strip() for s in _SENTENCE_SPLIT_RE.split(regulation) if len(s.strip()) >= 15]
    if not sentences:
        return _truncate_verbatim(regulation.strip(), MAX_EXCERPT_CHARS)
    target_words = set(_WORD_RE.findall(norm_ex))
    best, best_score = sentences[0], (-1.0, -1.0)
    for sentence in sentences:
        norm_sentence = _normalized_with_map(sentence)[0]
        words = set(_WORD_RE.findall(norm_sentence))
        overlap = len(target_words & words) / len(target_words) if target_words else 0.0
        score = (overlap, difflib.SequenceMatcher(None, norm_ex, norm_sentence, autojunk=False).ratio())
        if score > best_score:
            best, best_score = sentence, score
    return _truncate_verbatim(best, MAX_EXCERPT_CHARS)


def _finalize_anomalies(items: list[_Anomaly], regulation_text: str) -> list[dict]:
    norm_reg, index = _normalized_with_map(regulation_text)
    seen: set[tuple[str, str]] = set()
    cleaned: list[dict] = []
    for item in items:
        record = item.model_dump()
        key = (record["title"].casefold(), record["gap_description"].casefold())
        if key in seen:
            continue
        seen.add(key)
        record["title"] = _truncate(record["title"], MAX_TITLE_CHARS)
        record["regulation_excerpt"] = _ground_excerpt(
            record["regulation_excerpt"], regulation_text, norm_reg, index
        )
        if record["gap_type"] == "insufficient_information" or not record["current_state"]:
            record["current_state"] = NOT_SPECIFIED
        cleaned.append(record)

    cleaned.sort(key=lambda r: SEVERITY_RANK[r["severity"]])  # stable
    cleaned = cleaned[:MAX_ANOMALIES]
    return [
        {"id": f"ANOM-{i:03d}", **{k: r[k] for k in ANOMALY_ITEM_FIELDS}}
        for i, r in enumerate(cleaned, start=1)
    ]


def _validate_analysis_inputs(regulation_text: Any, state: Any) -> str:
    if not isinstance(regulation_text, str):
        raise ValueError("regulation_text must be a string")
    if not regulation_text.strip():
        raise ValueError("regulation_text must not be empty")
    if len(regulation_text) > MAX_REGULATION_CHARS:
        raise ValueError(f"regulation_text exceeds {MAX_REGULATION_CHARS} characters")
    if not isinstance(state, dict):
        raise ValueError("current_company_state_dict must be a dict")
    if not state:
        raise ValueError("current_company_state_dict must not be empty")
    try:
        state_json = json.dumps(state, indent=2, sort_keys=True, default=str)
    except Exception as exc:  # TypeError, ValueError, RecursionError, a failing __str__ ...
        raise ValueError(
            f"current_company_state_dict is not JSON-serializable or too deeply nested ({type(exc).__name__})"
        ) from None
    if len(state_json) > MAX_STATE_CHARS:
        raise ValueError(f"current_company_state_dict exceeds {MAX_STATE_CHARS} serialized characters")
    return state_json


def analyze_compliance_gap(
    regulation_text: str, current_company_state_dict: dict, *, api_key: str | None = None
) -> list[dict]:
    """Compare a regulation against the company's current state and list the gaps.

    Returns anomaly dicts sorted most-severe first, with ids ANOM-001, ANOM-002, ...
    An empty list means no gaps were found. `api_key` lets the end user supply their own
    Anthropic key (default: ANTHROPIC_API_KEY). Raises ValueError on bad input and
    LLMError (or a subclass) when the model cannot produce a valid result.
    """
    state_json = _validate_analysis_inputs(regulation_text, current_company_state_dict)
    _check_api_key(api_key)
    prompt = build_analysis_prompt(regulation_text, state_json)

    # call_llm already retries unusable output (and its LLMOutputError propagates), so
    # this loop only re-asks when the JSON parses but fails schema validation.
    for attempt in range(1, MAX_ATTEMPTS + 1):
        payload = call_llm(
            prompt, ANALYSIS_SYSTEM_PROMPT, json_mode=True, schema=ANALYSIS_SCHEMA, api_key=api_key
        )
        try:
            parsed = _AnalysisPayload.model_validate(payload)
        except ValidationError as exc:
            logger.warning(
                "analyze_compliance_gap attempt %d/%d: schema validation failed (%d errors)",
                attempt, MAX_ATTEMPTS, exc.error_count(),
            )
            continue
        return _finalize_anomalies(parsed.anomalies, regulation_text)
    raise LLMOutputError(f"analysis output failed schema validation {MAX_ATTEMPTS} times")


# --------------------------------------------------------------------------- audit trail

_OWNER_BY_CATEGORY = {
    "data_retention": "Data Protection Officer",
    "access_control": "Chief Information Security Officer",
    "security": "Chief Information Security Officer",
    "privacy_consent": "Data Protection Officer",
    "reporting": "Head of Compliance",
    "governance": "Chief Compliance Officer",
    "other": "Head of Compliance",
}
_TIMEFRAME_BY_SEVERITY = {
    "critical": "within 7 days",
    "high": "within 14 days",
    "medium": "within 30 days",
    "low": "within 90 days",
}
_GAP_TYPE_LABEL = {
    "non_compliant": "Non-compliant",
    "insufficient_information": "Insufficient information",
}
_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?Z?)?\b")


def _normalize_audit_items(anomalies: Any) -> list[dict]:
    if not isinstance(anomalies, list):
        raise ValueError("anomalies must be a list")
    items: list[dict] = []
    for position, item in enumerate(anomalies, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"anomaly #{position} is not a dict")
        for field in ("title", "gap_description"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError(f"anomaly #{position} has no {field}")
        record = {k: v for k, v in item.items()}
        for key in OUTPUT_KEYS:
            value = record.get(key)
            record[key] = value.strip() if isinstance(value, str) else ("" if value is None else str(value))
        record["severity"] = record["severity"].lower() or "medium"
        record["category"] = record["category"].lower() or "other"
        record["gap_type"] = record["gap_type"].lower() or "non_compliant"
        record["current_state"] = record["current_state"] or NOT_SPECIFIED
        items.append(record)

    used = {r["id"] for r in items if r["id"]}
    counter = 0
    for record in items:
        if not record["id"]:
            counter += 1
            while f"ANOM-{counter:03d}" in used:
                counter += 1
            record["id"] = f"ANOM-{counter:03d}"
            used.add(record["id"])
    return items


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def _audit_header(iso: str, report_id: str, model: str) -> list[str]:
    return [
        "# Compliance Audit Log",
        f"**Report ID:** {report_id}",
        f"**Generated (UTC):** {iso}",
        f"**Detected by:** AI Compliance Engine (model: {model})",
        "",
    ]


def _render_no_gaps(iso: str, report_id: str, model: str) -> str:
    lines = _audit_header(iso, report_id, model) + [
        "## 1. Executive Summary",
        "",
        "No compliance gaps detected. The automated gap analysis compared the company state "
        "against every obligation in the supplied regulation text and found no anomalies. "
        "No remediation is required at this time.",
        "",
        "## 2. Findings Summary",
        "",
        "| ID | Title | Severity | Gap Type | Status |",
        "| --- | --- | --- | --- | --- |",
        "| — | No compliance gaps detected | — | — | — |",
        "",
        "## 3. Detailed Findings",
        "",
        "No findings. The company state is compliant with the supplied regulation text.",
        "",
        "## 4. Audit Trail",
        "",
        "| Timestamp (UTC) | Event | Actor |",
        "| --- | --- | --- |",
        f"| {iso} | Compliance gap analysis completed: 0 anomalies detected | AI Compliance Engine |",
        f"| {iso} | Audit log {report_id} generated | AI Compliance Engine |",
        "",
    ]
    return "\n".join(lines)


def _remediation_steps(text: str) -> list[str]:
    text = " ".join(text.split())
    if not text:
        return ["Define and implement a remediation plan for this gap."]
    parts = [p.strip() for p in re.split(r"(?<=[.!?])\s+", text) if p.strip()]
    return parts or [text]


def _render_audit_fallback(anomalies: list[dict], iso: str, report_id: str, model: str) -> str:
    """Deterministic audit log that follows the required structure, with no LLM involved."""
    counts = {s: sum(1 for a in anomalies if a["severity"] == s) for s in SEVERITY_RANK}
    breakdown = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_RANK if counts[s])
    other = len(anomalies) - sum(counts.values())
    if other:
        breakdown += (", " if breakdown else "") + f"{other} unrated"
    top = [a for a in anomalies if a["severity"] in ("critical", "high")]
    posture = (
        f"Priority attention is required for {len(top)} critical or high severity finding(s), "
        f"led by {top[0]['id']} ({top[0]['title']})."
        if top
        else "No critical or high severity findings were detected."
    )
    lines = _audit_header(iso, report_id, model) + [
        "## 1. Executive Summary",
        "",
        f"The automated compliance gap analysis detected {len(anomalies)} anomal"
        f"{'y' if len(anomalies) == 1 else 'ies'} ({breakdown}). {posture} "
        "All findings are open and each has a proposed remediation plan below.",
        "",
        "## 2. Findings Summary",
        "",
        "| ID | Title | Severity | Gap Type | Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for a in anomalies:
        gap_label = _GAP_TYPE_LABEL.get(a["gap_type"], a["gap_type"] or "Unspecified")
        lines.append(
            f"| {_cell(a['id'])} | {_cell(a['title'])} | {_cell(a['severity'].capitalize())} "
            f"| {_cell(gap_label)} | Open |"
        )
    lines += ["", "## 3. Detailed Findings", ""]
    for a in anomalies:
        owner = _OWNER_BY_CATEGORY.get(a["category"], "Head of Compliance")
        timeframe = _TIMEFRAME_BY_SEVERITY.get(a["severity"], "within 30 days")
        excerpt = a["regulation_excerpt"] or "Not provided"
        lines += [
            f"### {a['id']} — {a['title']}",
            "",
            f"- **Detected at (UTC):** {iso}",
            "- **Detection method:** Automated AI gap analysis of the company state against the supplied regulation text",
            f"- **Severity:** {a['severity'].capitalize() or 'Unrated'} | **Category:** {a['category'] or 'other'}",
            f"- **Regulation requirement:** {a['regulation_requirement'] or 'Not provided'}",
            f"- **Regulation excerpt:** \"{' '.join(excerpt.split())}\"",
            f"- **Current state:** {a['current_state']}",
            f"- **Gap:** {a['gap_description']}",
            "- **Proposed remediation plan:**",
        ]
        steps = _remediation_steps(a["recommended_remediation"])
        steps.append("Verify the fix with evidence and close the finding in the compliance register.")
        lines += [f"  {n}. {step}" for n, step in enumerate(steps, start=1)]
        lines += [
            f"  - **Suggested owner:** {owner}",
            f"  - **Target timeframe:** {timeframe} of the report date",
            "- **Status:** Open",
            "",
        ]
    lines += [
        "## 4. Audit Trail",
        "",
        "| Timestamp (UTC) | Event | Actor |",
        "| --- | --- | --- |",
        f"| {iso} | Compliance gap analysis completed: {len(anomalies)} anomalies detected | AI Compliance Engine |",
    ]
    for a in anomalies:
        lines.append(f"| {iso} | {_cell(a['id'])} logged ({_cell(a['severity'] or 'unrated')}) | AI Compliance Engine |")
    lines += [f"| {iso} | Audit log {report_id} generated | AI Compliance Engine |", ""]
    return "\n".join(lines)


def _strip_markdown_fences(text: str) -> str:
    text = _strip_fences(text)
    # Drop any preamble the model wrote before the title line.
    match = re.search(r"^# Compliance Audit Log\s*$", text, re.MULTILINE)
    if match and match.start() > 0:
        text = text[match.start():]
    # A fenced block with prose around it leaves an unmatched closing fence: cut from there.
    fences = list(re.finditer(r"^\s*```[^\n]*$", text, re.MULTILINE))
    if len(fences) % 2 == 1:
        text = text[: fences[-1].start()]
    return text.strip() + "\n"


def _audit_is_valid(markdown: str, iso: str, anomalies: list[dict]) -> bool:
    """Section 5.3 checks, plus required headings and no invented dates or times."""
    if not markdown.startswith("# Compliance Audit Log"):
        return False
    if iso not in markdown:
        return False
    if any(a["id"] not in markdown for a in anomalies):
        return False
    for heading in ("## 1. Executive Summary", "## 2. Findings Summary", "## 3. Detailed Findings", "## 4. Audit Trail"):
        if heading not in markdown:
            return False
    # Dates that appear in the input anomalies may be quoted; any other date or time is invented.
    haystack = " ".join(" ".join(str(v).split()) for a in anomalies for v in a.values())
    allowed = set(_DATE_RE.findall(haystack))
    for found in _DATE_RE.findall(" ".join(markdown.replace(iso, " ").split())):
        if found not in allowed:
            return False
    return True


def _resolve_generated_at(generated_at: Any) -> datetime:
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)
    if not isinstance(generated_at, datetime):
        raise ValueError("generated_at must be a datetime or None")
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")
    try:
        return generated_at.astimezone(timezone.utc).replace(microsecond=0)
    except (OverflowError, OSError, ValueError):
        raise ValueError("generated_at is out of range") from None


def generate_audit_trail(
    anomalies: list[dict], generated_at: datetime | None = None, *, api_key: str | None = None
) -> str:
    """Turn anomalies into a formal Markdown compliance audit log.

    Always returns a Markdown string that follows the required structure. An empty list
    produces a deterministic "no gaps" log without calling the LLM. If the model's output
    fails validation twice, a deterministic renderer is used instead. `api_key` lets the end
    user supply their own Anthropic key (default: ANTHROPIC_API_KEY). Raises ValueError on
    bad input and LLMError if the provider cannot be reached.
    """
    items = _normalize_audit_items(anomalies)
    _check_api_key(api_key)
    when = _resolve_generated_at(generated_at)
    iso = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    report_id = "AUD-" + when.strftime("%Y%m%dT%H%M%SZ")
    model = _model_name()

    if not items:
        return _render_no_gaps(iso, report_id, model)

    payload = [{k: r[k] for k in OUTPUT_KEYS} for r in items]
    prompt = build_audit_prompt(
        json.dumps(payload, indent=2, ensure_ascii=False), iso, report_id, model
    )
    for attempt in range(1, AUDIT_ATTEMPTS + 1):
        try:
            text = call_llm(prompt, AUDIT_SYSTEM_PROMPT, json_mode=False, api_key=api_key)
        except LLMOutputError as exc:
            logger.warning("generate_audit_trail attempt %d/%d: %s", attempt, AUDIT_ATTEMPTS, exc)
            break  # call_llm already retried; go straight to the fallback
        markdown = _strip_markdown_fences(str(text))
        if _audit_is_valid(markdown, iso, items):
            return markdown
        logger.warning("generate_audit_trail attempt %d/%d: output failed validation", attempt, AUDIT_ATTEMPTS)

    logger.warning("generate_audit_trail: using deterministic fallback renderer")
    return _render_audit_fallback(items, iso, report_id, model)


# --------------------------------------------------------------------------- smoke test

_DEMO_REGULATION = """Data Protection and Retention Regulation 2026, Section 4.

4.1 Every regulated entity must retain customer transaction records for a minimum of 90 days.
4.2 Personal data must be encrypted at rest using industry-standard encryption.
4.3 In the event of a personal data breach, the entity must notify the regulator within 72 hours of becoming aware of it.
4.4 Every regulated entity must appoint a Data Protection Officer (DPO).
4.5 Access to customer data must be reviewed at least once every quarter."""

_DEMO_STATE = {
    "data_retention_days": 30,
    "encryption_at_rest": True,
    "breach_notification_hours": 96,
    "dpo_appointed": False,
}

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    found = analyze_compliance_gap(_DEMO_REGULATION, _DEMO_STATE)
    print(json.dumps(found, indent=2, ensure_ascii=False))
    print()
    print(generate_audit_trail(found))
