# Codex + ChatGPT Local Usage Dashboard

A dependency-free, localhost-only dashboard for recorded Codex usage plus optional locally estimated ChatGPT imports.

## Run

```bash
cd /path/to/codex_usage_dashboard
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

Prompt Explorer adds a second roll-up level. It totals every contributing turn and
advancing token snapshot/model call for the root user prompt, counts locally detected
permission-approval tool calls, and attaches explicit approval-only follow-up turns to
the preceding prompt. Request Explorer remains available for the underlying turn rows.

Subagent rollout files can embed a timestamp-rewritten replay of their parent thread.
The index suppresses those replay duplicates by stable `turn_id`, keeps the original
parent record, and attaches only the subagent's native work to the prompt that spawned
it. Short aborted/restarted handoffs of the same prompt are also grouped together while
their individual turn rows remain visible in Request Explorer.

Only a whitespace-normalized 180-character user-request preview is retained in the in-memory index and returned to the UI. Assistant responses, reasoning text, tool inputs/outputs, environment content, and full prompt bodies are not retained or logged.

Before display, previews redact common API-key, access-token, password, private
home-path, local account-name, email, JWT, and cloud-credential patterns. Local paths
below the current user's home directory are shown with `~` instead of the account name.

## Recorded tokens versus estimated credits

Token fields come directly from Codex rollouts. `input_tokens` includes cached input, so the dashboard derives:

```text
non-cached input = max(input tokens - cached input tokens, 0)
```

Estimated credits use the editable per-million-token rates in `config.json`:

```text
non-cached input × input rate
+ cached input × cached rate
+ output × output rate
```

`reasoning_output_tokens` is a subset of `output_tokens` in the observed rollouts, so it is shown separately but not charged a second time. These estimates are not exact billing values; local session files are not an OpenAI billing ledger.

GPT-6.1 Sol, GPT-6 Sol, GPT-6 Astra, and GPT-6 Luna use the published
[Standard-speed credit rates](https://learn.chatgpt.com/docs/pricing#token-rates),
verified October 21, 2026. Codex credits have no separate cache-write charge.
Unknown models are marked unpriced; the legacy `default` rate is never applied
silently. Summary totals include only priced usage and expose `unpriced_requests`.
Diagnostics list `unpriced_models`.

Calendar summaries and timeline buckets use token-event timestamps, so a turn that
starts in September and continues in October contributes only its October tokens
to October. Request and Prompt Explorers show the complete turn/prompt estimates.
Token events are priced using the model recorded when the usage occurred.
The separate **Credit comparison · month (UTC)** card uses UTC month boundaries;
**Current month (local)** retains the configured local timezone. This makes the
period difference visible when comparing with an external usage dashboard.

Codex Usage & Billing remains the source for actual credit consumption. Its period,
included allowances, speed modes, discounts, or workspace scope can differ from
the local calendar-month estimate. The dashboard does not rescale usage to match
a manually reported balance.

## API

- `GET /api/data` — summaries, searchable/sortable request rows, and diagnostics
- `GET /api/prompts` — searchable/sortable root-prompt totals
- `GET /api/prompt?id=...` — one prompt total plus its contributing request rows
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
