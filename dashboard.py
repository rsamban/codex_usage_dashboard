#!/usr/bin/env python3
"""Local, read-only Codex session usage dashboard."""

import argparse
import csv
import gzip
import hashlib
import json
import os
import re
import sys
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
IMPORT_DIR = ROOT / "imports"
DEFAULT_CODEX_HOME = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
TOKEN_KEYS = (
    "input_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "total_tokens",
)

DEFAULT_CONFIG = {
    "timezone": "America/Denver",
    "codex_home": str(DEFAULT_CODEX_HOME),
    "include_archived": True,
    "chatgpt": {
        "mode": "fixed",
        "fixed_message_credits": 10,
        "pro_message_credits": 50,
        "unlimited_models": ["Instant", "GPT-5.6 Luna"],
    },
    # Estimated credits per 1M recorded tokens. Input means non-cached input.
    "rates": {
        "GPT-5.6 Sol": {"input": 100, "cached": 10, "cache_write": 100, "output": 500},
        "GPT-5.6 Terra": {"input": 50, "cached": 5, "cache_write": 50, "output": 300},
        "GPT-5.6 Luna": {"input": 5, "cached": 0.5, "cache_write": 5, "output": 30},
        "GPT-5.5": {"input": 125, "cached": 12.5, "cache_write": 125, "output": 750},
        "GPT-5.4": {"input": 62.5, "cached": 6.25, "cache_write": 62.5, "output": 375},
        "GPT-5.4 mini": {"input": 18.75, "cached": 1.875, "cache_write": 18.75, "output": 113},
        "GPT-5.3-Codex": {"input": 43.75, "cached": 4.375, "cache_write": 43.75, "output": 350},
        "GPT-5.2": {"input": 43.75, "cached": 4.375, "cache_write": 43.75, "output": 350},
        "default": {"input": 100, "cached": 10, "cache_write": 100, "output": 500},
    },
}

CONFIG_PATH = ROOT / "config.json"


def load_config(path=CONFIG_PATH):
    base = json.loads(json.dumps(DEFAULT_CONFIG))
    if not path.exists():
        return base
    try:
        supplied = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return base
    for key, value in supplied.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key].update(value)
        else:
            base[key] = value
    if isinstance(supplied.get("rates"), dict):
        base["rates"] = {**DEFAULT_CONFIG["rates"], **supplied["rates"]}
    return base


CONFIG = load_config()


def iso_parse(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def num(value):
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def integerish(value):
    value = num(value)
    return int(value) if value.is_integer() else value


def empty_usage():
    return {key: 0.0 for key in TOKEN_KEYS}


def usage_dict(value):
    value = value if isinstance(value, dict) else {}
    return {key: num(value.get(key)) for key in TOKEN_KEYS}


def add_usage(target, increment):
    for key in TOKEN_KEYS:
        target[key] += max(0, num(increment.get(key)))


def first_text(payload):
    if not isinstance(payload, dict):
        return ""
    if isinstance(payload.get("message"), str):
        return payload["message"]
    content = payload.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            item["text"] for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        )
    return ""


def is_private_context(text):
    stripped = (text or "").lstrip().lower()
    return stripped.startswith((
        "<environment_context>", "<system", "<developer", "# agents.md instructions",
        "<permissions instructions>", "<app-context>", "<skills_instructions>",
    ))


def redact_sensitive_text(text):
    """Redact common local identifiers and credential shapes before UI display."""
    value = str(text or "")
    home = str(Path.home())
    if home:
        value = value.replace(home, "~")
    account = Path.home().name
    account_variants = {account, account.replace(".", " "), account.replace("_", " "), account.replace("-", " ")}
    account_variants.update(part for part in re.split(r"[._-]+", account) if len(part) >= 3)
    for variant in sorted(account_variants, key=len, reverse=True):
        value = re.sub(re.escape(variant), "[user redacted]", value, flags=re.I)
    value = re.sub(r"/Users/[^/\s`\"']+", "~", value)
    value = re.sub(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "[private key redacted]",
        value,
        flags=re.I | re.S,
    )
    value = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[email redacted]", value, flags=re.I)
    value = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "[API key redacted]", value)
    value = re.sub(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{12,}\b", "[token redacted]", value)
    value = re.sub(r"\bAKIA[A-Z0-9]{16}\b", "[access key redacted]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[JWT redacted]", value)
    value = re.sub(r"(?i)(AccountKey=)[A-Za-z0-9+/=]{12,}", r"\1[redacted]", value)
    value = re.sub(
        r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token|password|credential)\b\s*([=:])\s*[\"']?[^\s\"',;]+",
        r"\1\2[redacted]",
        value,
    )
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}", "Bearer [redacted]", value)
    return value


def redact_local_path(value):
    if not value:
        return ""
    return redact_sensitive_text(str(value))


def human_preview(text, limit=180):
    compact = re.sub(r"\s+", " ", redact_sensitive_text(text)).strip()
    return compact if len(compact) <= limit else compact[: limit - 1] + "…"


def normalize_model(model):
    if not model:
        return "unknown"
    raw = str(model).strip()
    aliases = {
        "gpt-5.2-codex": "GPT-5.2",
        "gpt-5.3-codex": "GPT-5.3-Codex",
        "gpt-5.4-mini": "GPT-5.4 mini",
        "gpt-5.5": "GPT-5.5",
        "gpt-5.5-instant": "GPT-5.5",
        "gpt-5.6": "GPT-5.6 Sol",
        "gpt-5.6-sol": "GPT-5.6 Sol",
        "gpt-5.6-terra": "GPT-5.6 Terra",
        "gpt-5.6-luna": "GPT-5.6 Luna",
    }
    return aliases.get(raw.lower(), raw)


def classify_prompt(prompt):
    text = (prompt or "").lower()
    rules = (
        ("code review", r"\b(code review|review (this|the|my) (code|diff|pr)|pull request|review comments?)\b"),
        ("debugging", r"\b(debug|bug|error|exception|traceback|broken|failing|failure|troubleshoot|root cause|fix)\b"),
        ("testing", r"\b(test|tests|testing|coverage|fixture|assertion|spec)\b"),
        ("research", r"\b(research|look up|browse|search the web|documentation|docs|compare options)\b"),
        ("planning/reasoning", r"\b(plan|planning|design|architecture|analy[sz]e|reason|explain|strategy|approach)\b"),
        ("coding", r"\b(code|implement|refactor|function|class|api|python|javascript|typescript|rust|react|sql|git|repo|file|build|add|update|create)\b"),
    )
    for category, pattern in rules:
        if re.search(pattern, text, re.I):
            return category
    return "other"


def is_approval_response(prompt):
    """Identify explicit approval-only follow-ups without sending text elsewhere."""
    text = re.sub(r"\s+", " ", prompt or "").strip().lower()
    if not text:
        return False
    short = r"(y|yes|ok|okay|approve|approved|allow|continue|proceed|go ahead|run it|do it|permission granted)[.!]?"
    return bool(re.fullmatch(short, text) or text.startswith(("approved command", "approval granted")))


def estimate_credits(model, usage, config=None):
    config = config or CONFIG
    rates = config.get("rates", {})
    normalized = normalize_model(model)
    rate = rates.get(normalized) or rates.get(str(model)) or rates.get("default", DEFAULT_CONFIG["rates"]["default"])
    total_input = num(usage.get("input_tokens"))
    cached = min(total_input, num(usage.get("cached_input_tokens")))
    non_cached = max(0, total_input - cached)
    cache_write = num(usage.get("cache_write_input_tokens"))
    # reasoning_output_tokens is diagnostic detail within output_tokens, not extra output.
    output = num(usage.get("output_tokens"))
    credits = (
        non_cached * num(rate.get("input"))
        + cached * num(rate.get("cached"))
        + cache_write * num(rate.get("cache_write", rate.get("input")))
        + output * num(rate.get("output"))
    ) / 1_000_000
    return round(credits, 6)


def rate_limit_snapshot(rate_limits):
    if not isinstance(rate_limits, dict):
        return {}
    result = {"plan_type": rate_limits.get("plan_type"), "credits": rate_limits.get("credits")}
    for key in ("primary", "secondary"):
        item = rate_limits.get(key)
        if isinstance(item, dict):
            result[key] = {name: item.get(name) for name in ("used_percent", "window_minutes", "resets_at")}
    return result


def iter_rollout_files(codex_home, include_archived=True):
    roots = [(Path(codex_home).expanduser() / "sessions", False)]
    if include_archived:
        roots.append((Path(codex_home).expanduser() / "archived_sessions", True))
    found = []
    for root, archived in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and (path.name.endswith(".jsonl") or path.name.endswith(".jsonl.gz")):
                found.append((path, archived))
    yield from sorted(found, key=lambda item: str(item[0]))


def _new_turn(timestamp, turn_id, meta, lifecycle, prompt="", prompt_source=None, prompt_client_id=None, replayed=False):
    workspace = meta.get("cwd") or ""
    return {
        "timestamp": timestamp.isoformat() if timestamp else None,
        "turn_id": turn_id,
        "model": meta.get("model"),
        "reasoning_effort": meta.get("effort"),
        "workspace": workspace,
        "project": Path(workspace).name if workspace else "",
        "prompt": prompt,
        "prompt_source": prompt_source,
        "prompt_client_id": prompt_client_id,
        "usage": empty_usage(),
        "usage_methods": set(),
        "model_requests": 0,
        "approval_requests": 0,
        "replayed": replayed,
        "lifecycle": lifecycle,
        "rate_limits": {},
    }


def parse_rollout(path, archived=False, config=None):
    """Parse one rollout into one record per request/turn, never per token event."""
    config = config or CONFIG
    path = Path(path)
    requests = []
    diag = {
        "file": redact_local_path(path), "parsed": False, "archived": archived, "parse_errors": 0,
        "unknown_event_types": Counter(), "unknown_payload_types": Counter(),
        "duplicate_token_events_suppressed": 0, "counter_resets": 0,
        "rate_limit_only_events": 0, "unassigned_token_events": 0,
        "session_ids": set(), "request_usage_missing": 0,
    }
    known_top = {"session_meta", "turn_context", "event_msg", "response_item", "world_state", "compacted"}
    known_event = {
        "user_message", "agent_message", "agent_reasoning", "token_count", "task_started",
        "task_complete", "turn_aborted", "thread_settings_applied", "patch_apply_end",
        "web_search_end", "item_completed", "mcp_tool_call_end", "context_compacted",
    }
    meta = {"session_id": None, "thread_id": None, "cwd": "", "model": None, "effort": None}
    pending = None
    active = None
    previous_total = None
    sequence = 0
    latest_rate_limits = {}
    native_session_id = None
    native_session_timestamp = None
    subagent_parent_thread_id = None

    def set_prompt(turn, text, source, ts, client_id=None):
        nonlocal pending
        if not text or is_private_context(text):
            return
        candidate = {"text": text, "source": source, "timestamp": ts, "client_id": client_id}
        if turn is None:
            # event_msg is the canonical user event when both representations exist.
            if pending is None or source == "event_msg" or pending.get("source") != "event_msg":
                pending = candidate
            return
        if not turn["prompt"] or source == "event_msg" and turn.get("prompt_source") != "event_msg":
            turn["prompt"] = text
            turn["prompt_source"] = source
            turn["prompt_client_id"] = client_id or turn.get("prompt_client_id")

    def finish(turn, status, end_ts=None):
        nonlocal sequence
        if turn is None:
            return
        sequence += 1
        usage = {key: integerish(value) for key, value in turn["usage"].items()}
        if not usage["total_tokens"] and (usage["input_tokens"] or usage["output_tokens"]):
            usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
        usage_available = any(num(usage[key]) for key in TOKEN_KEYS)
        if not usage_available:
            diag["request_usage_missing"] += 1
        prompt = turn.get("prompt") or ""
        category = classify_prompt(prompt)
        is_subagent = bool(subagent_parent_thread_id)
        is_replayed = bool(is_subagent and turn.get("replayed"))
        session_id = meta.get("session_id")
        if is_subagent and not is_replayed:
            session_id = native_session_id or session_id
        turn_id = turn.get("turn_id")
        stable = f"{path}|{session_id}|{turn_id}|{sequence}"
        record = {
            "id": hashlib.sha256(stable.encode()).hexdigest()[:24],
            "source": "codex",
            "source_confidence": "recorded tokens" if usage_available else "usage unavailable",
            "timestamp": turn.get("timestamp") or (end_ts.isoformat() if end_ts else None),
            "session_id": session_id,
            "thread_id": meta.get("thread_id") or session_id,
            "turn_id": turn_id,
            "model": normalize_model(turn.get("model") or meta.get("model")),
            "reasoning_effort": turn.get("reasoning_effort") or meta.get("effort"),
            "prompt_preview": human_preview(prompt),
            # A short normalized fingerprint survives local handoff/retry wrappers that
            # append different environment context to the same human-entered prompt.
            "prompt_fingerprint": hashlib.sha256(human_preview(prompt).encode()).hexdigest() if prompt else None,
            "category": category,
            "kind": "coding" if category in {"coding", "code review", "debugging", "testing"} else "chat",
            "workspace": redact_local_path(turn.get("workspace") or meta.get("cwd") or ""),
            "project": turn.get("project") or (Path(meta["cwd"]).name if meta.get("cwd") else ""),
            "status": status,
            "usage_available": usage_available,
            "usage_source": "+".join(sorted(turn["usage_methods"])) if turn["usage_methods"] else None,
            "model_requests": turn.get("model_requests", 0),
            "approval_requests": turn.get("approval_requests", 0),
            "_prompt_client_id": turn.get("prompt_client_id"),
            "_approval_response": is_approval_response(prompt),
            "non_cached_input_tokens": max(0, num(usage["input_tokens"]) - num(usage["cached_input_tokens"])),
            "file": redact_local_path(path),
            "archived": archived,
            "rate_limits": turn.get("rate_limits") or latest_rate_limits,
            "is_subagent": is_subagent,
            "is_replayed": is_replayed,
            "parent_thread_id": subagent_parent_thread_id,
            **usage,
        }
        record["non_cached_input_tokens"] = integerish(record["non_cached_input_tokens"])
        record["estimated_credits"] = estimate_credits(record["model"], record, config)
        requests.append(record)

    try:
        opener = gzip.open if path.name.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as stream:
            for raw in stream:
                try:
                    line = json.loads(raw)
                except (TypeError, ValueError):
                    diag["parse_errors"] += 1
                    continue
                timestamp = iso_parse(line.get("timestamp"))
                top_type = line.get("type")
                payload = line.get("payload") if isinstance(line.get("payload"), dict) else {}
                payload_type = payload.get("type")
                if top_type not in known_top:
                    diag["unknown_event_types"][str(top_type)] += 1
                if top_type == "event_msg" and payload_type not in known_event:
                    diag["unknown_payload_types"][str(payload_type)] += 1

                if top_type == "session_meta":
                    session_id = payload.get("id") or payload.get("session_id")
                    if native_session_id is None:
                        native_session_id = session_id
                        native_session_timestamp = iso_parse(payload.get("timestamp") or line.get("timestamp"))
                        source = payload.get("source")
                        if isinstance(source, dict):
                            subagent = source.get("subagent")
                            spawn = subagent.get("thread_spawn") if isinstance(subagent, dict) else None
                            if isinstance(spawn, dict):
                                subagent_parent_thread_id = spawn.get("parent_thread_id")
                    if session_id:
                        diag["session_ids"].add(str(session_id))
                        meta["session_id"] = session_id
                    meta["thread_id"] = payload.get("thread_id") or meta.get("thread_id")
                    meta["cwd"] = payload.get("cwd") or meta.get("cwd")
                    meta["model"] = payload.get("model") or meta.get("model")
                elif top_type == "turn_context":
                    meta["model"] = payload.get("model") or meta.get("model")
                    meta["effort"] = payload.get("effort") or payload.get("reasoning_effort") or meta.get("effort")
                    meta["cwd"] = payload.get("cwd") or meta.get("cwd")
                    if active is not None:
                        active["turn_id"] = payload.get("turn_id") or active.get("turn_id")
                        active["model"] = meta["model"]
                        active["reasoning_effort"] = meta["effort"]
                        active["workspace"] = meta["cwd"]
                        active["project"] = Path(meta["cwd"]).name if meta["cwd"] else ""
                elif top_type == "response_item" and payload_type in ("custom_tool_call", "function_call"):
                    raw_input = payload.get("input") if payload_type == "custom_tool_call" else payload.get("arguments")
                    if active is not None and "require_escalated" in str(raw_input or "").lower():
                        active["approval_requests"] += 1
                elif top_type == "response_item" and payload_type == "message" and payload.get("role") == "user":
                    set_prompt(active, first_text(payload), "response_item", timestamp)
                elif top_type == "event_msg" and payload_type == "user_message":
                    text = payload.get("message") or first_text(payload)
                    if active is not None and active["lifecycle"] == "inferred":
                        finish(active, "inferred", timestamp)
                        active = None
                    set_prompt(active, text, "event_msg", timestamp, payload.get("client_id"))
                elif top_type == "event_msg" and payload_type == "task_started":
                    if active is not None:
                        finish(active, "incomplete", timestamp)
                    prompt = pending["text"] if pending else ""
                    prompt_source = pending["source"] if pending else None
                    prompt_client_id = pending.get("client_id") if pending else None
                    start_ts = timestamp or (pending.get("timestamp") if pending else None)
                    started_at = num(payload.get("started_at"))
                    native_epoch = native_session_timestamp.timestamp() if native_session_timestamp else 0
                    replayed = bool(subagent_parent_thread_id and started_at and native_epoch and started_at < native_epoch - 1)
                    active = _new_turn(start_ts, payload.get("turn_id"), meta, True, prompt, prompt_source, prompt_client_id, replayed)
                    pending = None
                elif top_type == "event_msg" and payload_type == "token_count":
                    if isinstance(payload.get("rate_limits"), dict):
                        latest_rate_limits = rate_limit_snapshot(payload["rate_limits"])
                        if active is not None:
                            active["rate_limits"] = latest_rate_limits
                    info = payload.get("info")
                    if not isinstance(info, dict):
                        diag["rate_limit_only_events"] += 1
                        continue
                    total_raw = info.get("total_token_usage")
                    last_raw = info.get("last_token_usage")
                    total = usage_dict(total_raw) if isinstance(total_raw, dict) else None
                    last = usage_dict(last_raw) if isinstance(last_raw, dict) else None
                    increment = None
                    method = None
                    if total is not None:
                        if previous_total is None:
                            increment, method = total, "cumulative_delta"
                        else:
                            delta = {key: total[key] - previous_total[key] for key in TOKEN_KEYS}
                            if all(value == 0 for value in delta.values()):
                                diag["duplicate_token_events_suppressed"] += 1
                            elif any(value < 0 for value in delta.values()):
                                diag["counter_resets"] += 1
                                increment, method = (last or total), "last_after_reset"
                            else:
                                increment, method = delta, "cumulative_delta"
                        previous_total = total
                    elif last is not None:
                        increment, method = last, "last_token_usage"
                    if increment is None:
                        continue
                    if active is None and pending is not None:
                        active = _new_turn(pending.get("timestamp") or timestamp, None, meta, "inferred", pending["text"], pending["source"], pending.get("client_id"))
                        pending = None
                    if active is None:
                        diag["unassigned_token_events"] += 1
                        continue
                    add_usage(active["usage"], increment)
                    active["usage_methods"].add(method)
                    active["model_requests"] += 1
                elif top_type == "event_msg" and payload_type in ("task_complete", "turn_aborted"):
                    if active is not None:
                        active["turn_id"] = payload.get("turn_id") or active.get("turn_id")
                        finish(active, "complete" if payload_type == "task_complete" else "aborted", timestamp)
                        active = None
                    pending = None
        if active is not None:
            finish(active, "incomplete" if active["lifecycle"] is True else "inferred")
        elif pending is not None:
            orphan = _new_turn(pending.get("timestamp"), None, meta, "inferred", pending["text"], pending["source"], pending.get("client_id"))
            finish(orphan, "incomplete")
        diag["parsed"] = True
    except (OSError, EOFError, UnicodeError) as exc:
        diag["read_error"] = type(exc).__name__

    current_prompt = None
    for request in requests:
        approval_followup = request.pop("_approval_response", False)
        client_id = request.pop("_prompt_client_id", None)
        if not approval_followup or current_prompt is None:
            stable_prompt = client_id or request["id"]
            current_prompt = {
                "id": hashlib.sha256(f"prompt|{path}|{stable_prompt}".encode()).hexdigest()[:24],
                "preview": request.get("prompt_preview") or "",
            }
        request["prompt_id"] = current_prompt["id"]
        request["root_prompt_preview"] = current_prompt["preview"]
        request["is_approval_followup"] = approval_followup

    diag["unknown_event_types"] = dict(diag["unknown_event_types"])
    diag["unknown_payload_types"] = dict(diag["unknown_payload_types"])
    diag["session_ids"] = sorted(diag["session_ids"])
    diag["requests"] = len(requests)
    diag["latest_rate_limits"] = latest_rate_limits
    return requests, diag


def parse_import_file(path, config=None):
    config = config or CONFIG
    rows = []
    try:
        if path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
        elif path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data = data.get("usage") or data.get("events") or [data]
            rows = [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []
    except (OSError, ValueError, csv.Error):
        return []
    output = []
    for index, row in enumerate(rows):
        timestamp = row.get("timestamp") or row.get("date") or row.get("time")
        parsed = iso_parse(timestamp)
        if not timestamp:
            continue
        model = normalize_model(row.get("model") or "unknown")
        source = str(row.get("source") or "chatgpt").lower()
        category = str(row.get("category") or row.get("kind") or row.get("type") or "other").lower()
        usage = {key: num(row.get(key)) for key in TOKEN_KEYS}
        credits = num(row.get("credits") or row.get("estimated_credits") or row.get("credit_usage"))
        if not credits and source == "chatgpt":
            if "pro" in model.lower():
                credits = config["chatgpt"].get("pro_message_credits", 50)
            elif any(item.lower() in model.lower() for item in config["chatgpt"].get("unlimited_models", [])):
                credits = 0
            else:
                credits = config["chatgpt"].get("fixed_message_credits", 10)
        preview = human_preview(row.get("prompt") or row.get("message") or row.get("title") or "")
        request_id = hashlib.sha256(f"{path}|{index}".encode()).hexdigest()[:24]
        output.append({
            "id": request_id, "prompt_id": request_id,
            "source": source, "source_confidence": "locally estimated", "timestamp": parsed.isoformat() if parsed else str(timestamp),
            "session_id": None, "thread_id": None, "turn_id": None, "model": model,
            "reasoning_effort": row.get("reasoning_effort"), "prompt_preview": preview,
            "prompt_fingerprint": hashlib.sha256(preview.encode()).hexdigest() if preview else None,
            "root_prompt_preview": preview, "is_approval_followup": False,
            "category": category, "kind": "coding" if category in {"coding", "code review", "debugging", "testing"} else "chat",
            "workspace": redact_local_path(row.get("workspace") or ""), "project": row.get("project") or "",
            "status": "imported", "usage_available": any(usage.values()), "usage_source": "import",
            "model_requests": 1, "approval_requests": 0,
            "non_cached_input_tokens": max(0, usage["input_tokens"] - usage["cached_input_tokens"]),
            "file": redact_local_path(path), "archived": False, "rate_limits": {},
            "estimated_credits": round(credits, 6), **{key: integerish(value) for key, value in usage.items()},
        })
    return output


def reconcile_request_replays(requests):
    """Remove subagent history replays and attach native subagent work to its parent prompt."""
    chosen = {}
    passthrough = []
    replay_duplicates = 0
    for row in requests:
        turn_id = row.get("turn_id") if row.get("source") == "codex" else None
        if not turn_id:
            passthrough.append(row)
            continue
        current = chosen.get(turn_id)
        score = (not row.get("is_replayed"), bool(row.get("usage_available")), num(row.get("total_tokens")))
        if current is None:
            chosen[turn_id] = row
        else:
            replay_duplicates += 1
            current_score = (not current.get("is_replayed"), bool(current.get("usage_available")), num(current.get("total_tokens")))
            if score > current_score:
                chosen[turn_id] = row
    reconciled = passthrough + list(chosen.values())
    parents = defaultdict(list)
    for row in reconciled:
        if row.get("source") == "codex" and not row.get("is_subagent") and row.get("session_id"):
            parents[str(row["session_id"])].append(row)
    for rows in parents.values():
        rows.sort(key=lambda item: item.get("timestamp") or "")
    linked_subagents = 0
    for row in reconciled:
        parent_id = row.get("parent_thread_id")
        if not row.get("is_subagent") or row.get("is_replayed") or not parent_id:
            continue
        timestamp = row.get("timestamp") or ""
        candidates = [item for item in parents.get(str(parent_id), []) if (item.get("timestamp") or "") <= timestamp]
        if candidates:
            parent = candidates[-1]
            row["prompt_id"] = parent.get("prompt_id") or parent["id"]
            row["root_prompt_preview"] = parent.get("root_prompt_preview") or parent.get("prompt_preview") or ""
            linked_subagents += 1
    prompt_retries_linked = 0
    retry_groups = defaultdict(list)
    for row in reconciled:
        if row.get("source") == "codex" and row.get("session_id") and row.get("prompt_fingerprint") and not row.get("is_approval_followup"):
            retry_groups[(str(row["session_id"]), row["prompt_fingerprint"])].append(row)
    for group in retry_groups.values():
        group.sort(key=lambda item: item.get("timestamp") or "")
        previous = None
        for row in group:
            current_time = iso_parse(row.get("timestamp"))
            previous_time = iso_parse(previous.get("timestamp")) if previous else None
            if previous and current_time and previous_time and current_time - previous_time <= timedelta(minutes=15):
                row["prompt_id"] = previous.get("prompt_id") or previous["id"]
                row["root_prompt_preview"] = previous.get("root_prompt_preview") or previous.get("prompt_preview") or ""
                prompt_retries_linked += 1
            previous = row
    reconciled.sort(key=lambda row: row.get("timestamp") or "")
    return reconciled, {
        "replayed_request_duplicates_suppressed": replay_duplicates,
        "subagent_requests_linked": linked_subagents,
        "prompt_retries_linked": prompt_retries_linked,
    }


class SessionIndex:
    """Process-wide incremental index keyed by immutable file-stat fingerprints."""

    def __init__(self, config=None, import_dir=None):
        self.config = config or CONFIG
        self.import_dir = Path(import_dir) if import_dir else IMPORT_DIR
        self.entries = {}
        self.lock = threading.RLock()
        self.last_diagnostics = {}

    @staticmethod
    def fingerprint(path):
        stat = path.stat()
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)

    def refresh(self):
        with self.lock:
            codex_home = Path(self.config.get("codex_home", DEFAULT_CODEX_HOME)).expanduser()
            discovered = list(iter_rollout_files(codex_home, self.config.get("include_archived", True)))
            live_paths = {str(path) for path, _ in discovered}
            cache_hits = reparsed = skipped = 0
            for old_path in set(self.entries) - live_paths:
                del self.entries[old_path]
            for path, archived in discovered:
                key = str(path)
                try:
                    fingerprint = self.fingerprint(path)
                except OSError:
                    skipped += 1
                    continue
                if key in self.entries and self.entries[key]["fingerprint"] == fingerprint:
                    cache_hits += 1
                    continue
                requests, diag = parse_rollout(path, archived, self.config)
                self.entries[key] = {"fingerprint": fingerprint, "requests": requests, "diag": diag}
                reparsed += 1
            requests = [row for entry in self.entries.values() for row in entry["requests"]]
            for import_path in sorted(self.import_dir.glob("*")):
                if import_path.suffix.lower() in (".csv", ".json"):
                    requests.extend(parse_import_file(import_path, self.config))
            # Stable de-duplication protects against overlapping roots/import records.
            requests = list({row["id"]: row for row in requests}.values())
            requests, reconciliation = reconcile_request_replays(requests)
            file_diags = [entry["diag"] for entry in self.entries.values()]
            session_ids = {sid for diag in file_diags for sid in diag.get("session_ids", [])}
            unknown = Counter()
            unknown_payload = Counter()
            for diag in file_diags:
                unknown.update(diag.get("unknown_event_types", {}))
                unknown_payload.update(diag.get("unknown_payload_types", {}))
            dated = [row.get("timestamp") for row in requests if row.get("timestamp")]
            latest_limits = {}
            for diag in file_diags:
                if diag.get("latest_rate_limits"):
                    latest_limits = diag["latest_rate_limits"]
            prompts = aggregate_prompts(requests)
            self.last_diagnostics = {
                "session_files_discovered": len(discovered),
                "session_files_parsed": sum(bool(diag.get("parsed")) for diag in file_diags),
                "session_files_skipped": skipped + sum(not diag.get("parsed") for diag in file_diags),
                "archived_files": sum(archived for _, archived in discovered),
                "parse_errors": sum(diag.get("parse_errors", 0) for diag in file_diags),
                "sessions": len(session_ids), "requests": len(requests),
                "prompts": len(prompts),
                "model_requests": sum(item.get("model_requests", 0) for item in requests),
                "approval_requests": sum(item.get("approval_requests", 0) for item in requests),
                "oldest_request": min(dated) if dated else None, "newest_request": max(dated) if dated else None,
                "unknown_event_types": dict(unknown), "unknown_payload_types": dict(unknown_payload),
                "files_with_unknown_event_types": sum(bool(diag.get("unknown_event_types") or diag.get("unknown_payload_types")) for diag in file_diags),
                "requests_without_token_usage": sum(not row.get("usage_available") for row in requests if row.get("source") == "codex"),
                "duplicate_token_events_suppressed": sum(diag.get("duplicate_token_events_suppressed", 0) for diag in file_diags),
                **reconciliation,
                "counter_resets": sum(diag.get("counter_resets", 0) for diag in file_diags),
                "rate_limit_only_events": sum(diag.get("rate_limit_only_events", 0) for diag in file_diags),
                "unassigned_token_events": sum(diag.get("unassigned_token_events", 0) for diag in file_diags),
                "cache_hits_this_scan": cache_hits, "files_reparsed_this_scan": reparsed,
                "latest_rate_limits": latest_limits,
            }
            return requests, self.last_diagnostics


INDEX = SessionIndex()


def local_zone(config=None):
    try:
        return ZoneInfo((config or CONFIG).get("timezone", "America/Denver"))
    except Exception:
        return timezone.utc


def stats(rows):
    result = {
        "requests": len(rows), "estimated_credits": 0, "credits": 0,
        "input_tokens": 0, "cached_input_tokens": 0, "non_cached_input_tokens": 0,
        "cache_write_input_tokens": 0, "output_tokens": 0, "reasoning_output_tokens": 0,
        "total_tokens": 0, "codex_requests": 0, "chatgpt_requests": 0,
    }
    for row in rows:
        result["estimated_credits"] += num(row.get("estimated_credits"))
        for key in TOKEN_KEYS:
            result[key] += num(row.get(key))
        result["non_cached_input_tokens"] += num(row.get("non_cached_input_tokens"))
        if row.get("source") == "codex":
            result["codex_requests"] += 1
        if row.get("source") == "chatgpt":
            result["chatgpt_requests"] += 1
    result["estimated_credits"] = round(result["estimated_credits"], 6)
    result["credits"] = result["estimated_credits"]  # backwards-compatible UI field
    return {key: integerish(value) if key not in {"estimated_credits", "credits"} else value for key, value in result.items()}


def make_summary(requests, now=None, config=None):
    zone = local_zone(config)
    local_now = (now or datetime.now(timezone.utc)).astimezone(zone)
    hour_start = local_now.replace(minute=0, second=0, microsecond=0)
    today_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=today_start.weekday())
    month_start = today_start.replace(day=1)
    ranges = {
        "current_hour": (hour_start, local_now), "today": (today_start, local_now),
        "yesterday": (today_start - timedelta(days=1), today_start),
        "current_week": (week_start, local_now), "current_month": (month_start, local_now),
    }
    output = {"all_time": stats(requests), "all": stats(requests)}
    for name, (start, end) in ranges.items():
        chosen = []
        for row in requests:
            parsed = iso_parse(row.get("timestamp"))
            if parsed and start <= parsed.astimezone(zone) < end:
                chosen.append(row)
        output[name] = stats(chosen)
    return output


def bucket(value, mode):
    if mode == "hour":
        return value.replace(minute=0, second=0, microsecond=0)
    if mode == "day":
        return value.replace(hour=0, minute=0, second=0, microsecond=0)
    if mode == "week":
        start = value.replace(hour=0, minute=0, second=0, microsecond=0)
        return start - timedelta(days=start.weekday())
    return value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def timeline(requests, mode="day", limit=30, config=None):
    if mode not in {"hour", "day", "week", "month"}:
        mode = "day"
    groups = defaultdict(list)
    zone = local_zone(config)
    for row in requests:
        parsed = iso_parse(row.get("timestamp"))
        if parsed:
            groups[bucket(parsed.astimezone(zone), mode)].append(row)
    output = [{"bucket": key.isoformat(), **stats(groups[key])} for key in sorted(groups)]
    return output[-max(1, min(int(limit), 500)):]


def filter_requests(requests, query):
    source = query.get("source", ["all"])[0]
    category = query.get("category", ["all"])[0]
    search = query.get("q", [""])[0].strip().lower()
    rows = requests
    if source != "all":
        rows = [row for row in rows if row.get("source") == source]
    if category != "all":
        rows = [row for row in rows if row.get("category") == category]
    if search:
        fields = ("prompt_preview", "project", "workspace", "model", "reasoning_effort", "category", "turn_id")
        rows = [row for row in rows if any(search in str(row.get(field) or "").lower() for field in fields)]
    sort = query.get("sort", ["timestamp"])[0]
    allowed = {"timestamp", "model", "category", "project", "input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens", "total_tokens", "estimated_credits"}
    sort = sort if sort in allowed else "timestamp"
    descending = query.get("order", ["desc"])[0] != "asc"
    return sorted(rows, key=lambda row: (row.get(sort) is not None, row.get(sort) or ""), reverse=descending)


def aggregate_prompts(requests):
    """Roll request/turn records up to the root user prompt that initiated them."""
    groups = {}
    for row in requests:
        prompt_id = row.get("prompt_id") or row["id"]
        if prompt_id not in groups:
            groups[prompt_id] = {
                "id": prompt_id, "timestamp": row.get("timestamp"), "end_timestamp": row.get("timestamp"),
                "source": row.get("source"), "source_confidence": row.get("source_confidence"),
                "prompt_preview": row.get("root_prompt_preview") or row.get("prompt_preview") or "",
                "project": row.get("project") or "", "workspace": row.get("workspace") or "",
                "category": row.get("category") or "other", "kind": row.get("kind") or "chat",
                "models": set(), "reasoning_efforts": set(), "statuses": set(), "request_ids": [],
                "request_count": 0, "model_requests": 0, "approval_requests": 0,
                "usage_available": False, "estimated_credits": 0.0,
                "non_cached_input_tokens": 0.0,
                **empty_usage(),
            }
        group = groups[prompt_id]
        group["end_timestamp"] = max(group.get("end_timestamp") or "", row.get("timestamp") or "")
        if row.get("model"):
            group["models"].add(row["model"])
        if row.get("reasoning_effort"):
            group["reasoning_efforts"].add(row["reasoning_effort"])
        if row.get("status"):
            group["statuses"].add(row["status"])
        group["request_ids"].append(row["id"])
        group["request_count"] += 1
        group["model_requests"] += int(num(row.get("model_requests")))
        group["approval_requests"] += int(num(row.get("approval_requests")))
        group["usage_available"] = group["usage_available"] or bool(row.get("usage_available"))
        group["estimated_credits"] += num(row.get("estimated_credits"))
        group["non_cached_input_tokens"] += num(row.get("non_cached_input_tokens"))
        for key in TOKEN_KEYS:
            group[key] += num(row.get(key))
    output = []
    for group in groups.values():
        group["model"] = ", ".join(sorted(group.pop("models"))) or "unknown"
        group["reasoning_effort"] = ", ".join(sorted(group.pop("reasoning_efforts")))
        group["status"] = ", ".join(sorted(group.pop("statuses")))
        group["estimated_credits"] = round(group["estimated_credits"], 6)
        group["non_cached_input_tokens"] = integerish(group["non_cached_input_tokens"])
        for key in TOKEN_KEYS:
            group[key] = integerish(group[key])
        output.append(group)
    return output


def filter_prompts(prompts, query):
    source = query.get("source", ["all"])[0]
    category = query.get("category", ["all"])[0]
    search = query.get("q", [""])[0].strip().lower()
    rows = prompts
    if source != "all":
        rows = [row for row in rows if row.get("source") == source]
    if category != "all":
        rows = [row for row in rows if row.get("category") == category]
    if search:
        fields = ("prompt_preview", "project", "workspace", "model", "reasoning_effort", "category")
        rows = [row for row in rows if any(search in str(row.get(field) or "").lower() for field in fields)]
    sort = query.get("sort", ["timestamp"])[0]
    allowed = {
        "timestamp", "model", "category", "project", "request_count", "model_requests",
        "approval_requests", "input_tokens", "cached_input_tokens", "output_tokens",
        "reasoning_output_tokens", "total_tokens", "estimated_credits",
    }
    sort = sort if sort in allowed else "timestamp"
    descending = query.get("order", ["desc"])[0] != "asc"
    return sorted(rows, key=lambda row: (row.get(sort) is not None, row.get(sort) or ""), reverse=descending)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_json(self, data, status=200):
        body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path in {"/api/data", "/api/refresh"}:
            requests, diagnostics = INDEX.refresh()
            filtered = filter_requests(requests, query)
            try:
                limit = max(1, min(int(query.get("limit", ["1000"])[0]), 5000))
                offset = max(0, int(query.get("offset", ["0"])[0]))
            except ValueError:
                limit, offset = 1000, 0
            return self.send_json({
                "summary": make_summary(filtered), "requests": filtered[offset:offset + limit],
                "total_count": len(filtered), "diagnostics": diagnostics,
                "file_count": diagnostics["session_files_discovered"],
                "config": {"timezone": CONFIG.get("timezone"), "codex_home": CONFIG.get("codex_home"), "include_archived": CONFIG.get("include_archived")},
            })
        if parsed.path == "/api/timeline":
            requests, _ = INDEX.refresh()
            filtered = filter_requests(requests, query)
            mode = query.get("mode", ["day"])[0]
            try:
                limit = int(query.get("limit", ["30"])[0])
            except ValueError:
                limit = 30
            return self.send_json({"mode": mode, "rows": timeline(filtered, mode, limit)})
        if parsed.path == "/api/prompts":
            requests, _ = INDEX.refresh()
            prompts = filter_prompts(aggregate_prompts(requests), query)
            try:
                limit = max(1, min(int(query.get("limit", ["1000"])[0]), 5000))
                offset = max(0, int(query.get("offset", ["0"])[0]))
            except ValueError:
                limit, offset = 1000, 0
            return self.send_json({"prompts": prompts[offset:offset + limit], "total_count": len(prompts)})
        if parsed.path == "/api/prompt":
            requests, _ = INDEX.refresh()
            prompt_id = query.get("id", [""])[0]
            prompt = next((item for item in aggregate_prompts(requests) if item.get("id") == prompt_id), None)
            if prompt is None:
                return self.send_json({"error": "prompt not found"}, 404)
            prompt["requests"] = [row for row in requests if row.get("prompt_id") == prompt_id]
            return self.send_json(prompt)
        if parsed.path == "/api/diagnostics":
            _, diagnostics = INDEX.refresh()
            return self.send_json(diagnostics)
        if parsed.path == "/api/request":
            requests, _ = INDEX.refresh()
            request_id = query.get("id", [""])[0]
            row = next((item for item in requests if item.get("id") == request_id), None)
            return self.send_json(row or {"error": "request not found"}, 200 if row else 404)
        if parsed.path == "/api/config":
            return self.send_json(CONFIG)
        target = STATIC / ("index.html" if parsed.path == "/" else parsed.path.lstrip("/"))
        try:
            target = target.resolve()
            if STATIC.resolve() not in target.parents and target != STATIC.resolve():
                return self.send_error(404)
            if target.is_file():
                data = target.read_bytes()
                content_type = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}.get(target.suffix, "application/octet-stream")
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
        except OSError:
            pass
        self.send_error(404)

    def log_message(self, fmt, *args):
        # Request paths only; session content is never logged.
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main():
    parser = argparse.ArgumentParser(description="Local Codex + ChatGPT usage dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    requests, diagnostics = INDEX.refresh()
    print("Codex usage dashboard")
    print(f"Codex home (read only): {Path(CONFIG.get('codex_home', DEFAULT_CODEX_HOME)).expanduser()}")
    print(f"Indexed {diagnostics['session_files_discovered']} files and {len(requests)} requests")
    print(f"Open: http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
