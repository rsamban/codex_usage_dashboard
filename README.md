# Codex + ChatGPT Local Usage Dashboard

A dependency-free, localhost-only dashboard for recorded Codex usage plus optional locally estimated ChatGPT imports.

## Run

```bash
cd /Users/ramesh.sambandan/client_works/utils/codex_usage_dashboard
./run_dashboard.sh
```

Open <http://127.0.0.1:8787>.

The server binds to `127.0.0.1` unless `--host` is explicitly supplied. It makes no network requests and opens Codex session files only for reading.

## Codex accounting

At startup, and on each refresh, the index recursively discovers `*.jsonl` and `*.jsonl.gz` below:

- `~/.codex/sessions`
- `~/.codex/archived_sessions` when present and enabled

The first scan parses all history. Later scans compare device, inode, size, modification time, and change time, then reparse only new or changed files. The index is process-local so it never writes into `~/.codex`; restarting performs one fresh historical scan.

One dashboard row represents one Codex request/turn:

- Newer rollouts use `task_started`, `turn_context.turn_id`, and `task_complete`/`turn_aborted` boundaries.
- Older rollouts without task lifecycle events use canonical user-message boundaries.
- Repeated cumulative `token_count` snapshots are suppressed.
- Per-turn usage is the sum of advances in `total_token_usage`; `last_token_usage` is used only when cumulative data is absent or resets.
- Incomplete or tokenless requests remain visible and are flagged by diagnostics.

Only a whitespace-normalized 180-character user-request preview is retained in the in-memory index and returned to the UI. Assistant responses, reasoning text, tool inputs/outputs, environment content, and full prompt bodies are not retained or logged.

## Recorded tokens versus estimated credits

Token fields come directly from Codex rollouts. `input_tokens` includes cached input, so the dashboard derives:

```text
non-cached input = max(input tokens - cached input tokens, 0)
```

Estimated credits use the editable per-million-token rates in `config.json`:

```text
non-cached input × input rate
+ cached input × cached rate
+ cache-write input × cache-write rate
+ output × output rate
```

`reasoning_output_tokens` is a subset of `output_tokens` in the observed rollouts, so it is shown separately but not charged a second time. These estimates are not exact billing values; local session files are not an OpenAI billing ledger.

## API

- `GET /api/data` — summaries, searchable/sortable request rows, and diagnostics
- `GET /api/timeline?mode=hour|day|week|month` — time buckets
- `GET /api/request?id=...` — safe details for one indexed request
- `GET /api/diagnostics` — discovery, parser, and data-quality counters
- `GET /api/config` — active local configuration

`/api/data` accepts `source`, `category`, `q`, `sort`, `order`, `limit`, and `offset` query parameters.

## ChatGPT imports

ChatGPT support is preserved through local CSV/JSON files in `imports/`; see `imports/README.txt`. These rows are labeled `locally estimated`, while Codex rows are labeled `recorded tokens` (or `usage unavailable`). No browser-extension files are present in this project.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Fixtures are synthetic and sanitized. They cover normal and multi-request sessions, cumulative counters, duplicate snapshots, rate-limit-only events, session boundaries, missing usage, malformed JSONL, archived discovery, incremental updates, and estimate math.

## Limitations

- Model, reasoning effort, workspace, and turn IDs are shown only when recorded by that rollout version.
- Older request boundaries are inferred when lifecycle IDs are absent.
- Local files do not reveal an authoritative product credit charge, invoice amount, fast-mode multiplier, or every possible delegated/background product action.
- The first-party OpenAI usage/billing view remains authoritative for billing.
