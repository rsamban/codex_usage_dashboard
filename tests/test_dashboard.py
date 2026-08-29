import json
import tempfile
import time
import unittest
from pathlib import Path

import dashboard


BASE = "2026-08-01T12:00:00Z"


def event(top_type, payload, timestamp=BASE):
    return json.dumps({"timestamp": timestamp, "type": top_type, "payload": payload})


def usage(input_tokens, cached, output, reasoning=0, cache_write=0):
    return {
        "input_tokens": input_tokens,
        "cached_input_tokens": cached,
        "cache_write_input_tokens": cache_write,
        "output_tokens": output,
        "reasoning_output_tokens": reasoning,
        "total_tokens": input_tokens + output,
    }


def token(total, last=None, rate_limits=None):
    payload = {"type": "token_count", "info": {
        "total_token_usage": total,
        "last_token_usage": last if last is not None else total,
    }}
    if rate_limits is not None:
        payload["rate_limits"] = rate_limits
    return event("event_msg", payload)


def common_start(turn="turn-1", prompt="Implement a small parser"):
    return [
        event("session_meta", {"id": "session-safe", "cwd": "/workspace/demo"}),
        event("event_msg", {"type": "task_started", "turn_id": turn}),
        event("turn_context", {"turn_id": turn, "model": "gpt-5.6-sol", "effort": "medium", "cwd": "/workspace/demo"}),
        event("event_msg", {"type": "user_message", "message": prompt}),
    ]


def write_lines(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def parse(self, lines):
        path = self.root / "rollout-safe.jsonl"
        write_lines(path, lines)
        return dashboard.parse_rollout(path)

    def test_normal_request(self):
        lines = common_start() + [token(usage(100, 40, 20, 5)), event("event_msg", {"type": "task_complete", "turn_id": "turn-1"})]
        rows, diag = self.parse(lines)
        self.assertTrue(diag["parsed"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["input_tokens"], 100)
        self.assertEqual(rows[0]["non_cached_input_tokens"], 60)
        self.assertEqual(rows[0]["output_tokens"], 20)
        self.assertEqual(rows[0]["reasoning_output_tokens"], 5)
        self.assertEqual(rows[0]["total_tokens"], 120)
        self.assertEqual(rows[0]["reasoning_effort"], "medium")
        self.assertEqual(rows[0]["model_requests"], 1)
        self.assertNotIn("prompt", rows[0])

    def test_prompt_aggregation_includes_approval_followup_and_model_calls(self):
        lines = common_start("turn-1", "Implement the requested dashboard") + [
            token(usage(100, 20, 10)),
            event("response_item", {"type": "function_call", "name": "exec_command", "arguments": json.dumps({"sandbox_permissions": "require_escalated", "justification": "Allow local test"})}),
            token(usage(160, 40, 15), usage(60, 20, 5)),
            event("event_msg", {"type": "task_complete", "turn_id": "turn-1"}),
            event("event_msg", {"type": "task_started", "turn_id": "turn-2"}),
            event("turn_context", {"turn_id": "turn-2", "model": "gpt-5.6-sol", "effort": "medium"}),
            event("event_msg", {"type": "user_message", "message": "Approved"}),
            token(usage(200, 50, 20), usage(40, 10, 5)),
            event("event_msg", {"type": "task_complete", "turn_id": "turn-2"}),
        ]
        rows, _ = self.parse(lines)
        prompts = dashboard.aggregate_prompts(rows)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(prompts), 1)
        self.assertEqual(prompts[0]["request_count"], 2)
        self.assertEqual(prompts[0]["model_requests"], 3)
        self.assertEqual(prompts[0]["approval_requests"], 1)
        self.assertEqual(prompts[0]["total_tokens"], 220)
        self.assertEqual(prompts[0]["prompt_preview"], "Implement the requested dashboard")

    def test_multiple_requests_in_one_session(self):
        first = common_start("turn-1", "Implement feature") + [
            token(usage(100, 20, 10)), event("event_msg", {"type": "task_complete", "turn_id": "turn-1"}),
            event("event_msg", {"type": "task_started", "turn_id": "turn-2"}),
            event("turn_context", {"turn_id": "turn-2", "model": "gpt-5.6-sol", "effort": "high"}),
            event("event_msg", {"type": "user_message", "message": "Debug failure"}),
            token(usage(150, 40, 15), usage(50, 20, 5)),
            event("event_msg", {"type": "task_complete", "turn_id": "turn-2"}),
        ]
        rows, _ = self.parse(first)
        self.assertEqual(len(rows), 2)
        self.assertEqual([row["total_tokens"] for row in rows], [110, 55])
        self.assertEqual(rows[1]["category"], "debugging")

    def test_cumulative_counters_are_differenced_within_turn(self):
        lines = common_start() + [
            token(usage(100, 20, 10)),
            token(usage(260, 100, 25), usage(160, 80, 15)),
            event("event_msg", {"type": "task_complete", "turn_id": "turn-1"}),
        ]
        rows, _ = self.parse(lines)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["input_tokens"], 260)
        self.assertEqual(rows[0]["output_tokens"], 25)
        self.assertEqual(rows[0]["total_tokens"], 285)

    def test_duplicate_last_token_usage_is_suppressed(self):
        snapshot = usage(100, 20, 10)
        lines = common_start() + [token(snapshot), token(snapshot), event("event_msg", {"type": "task_complete", "turn_id": "turn-1"})]
        rows, diag = self.parse(lines)
        self.assertEqual(rows[0]["total_tokens"], 110)
        self.assertEqual(diag["duplicate_token_events_suppressed"], 1)

    def test_rate_limit_only_event_does_not_create_usage(self):
        lines = common_start() + [
            event("event_msg", {"type": "token_count", "info": None, "rate_limits": {"plan_type": "business"}}),
            event("event_msg", {"type": "task_complete", "turn_id": "turn-1"}),
        ]
        rows, diag = self.parse(lines)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["usage_available"])
        self.assertEqual(diag["rate_limit_only_events"], 1)

    def test_session_boundaries_reset_accounting(self):
        home = self.root / "codex"
        for number in (1, 2):
            lines = common_start(f"turn-{number}") + [token(usage(100, 10, 10)), event("event_msg", {"type": "task_complete", "turn_id": f"turn-{number}"})]
            write_lines(home / "sessions" / str(number) / f"rollout-{number}.jsonl", lines)
        index = dashboard.SessionIndex({**dashboard.DEFAULT_CONFIG, "codex_home": str(home)}, self.root / "imports")
        rows, diag = index.refresh()
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(row["total_tokens"] for row in rows), 220)
        self.assertEqual(diag["session_files_discovered"], 2)

    def test_missing_token_event_is_reported(self):
        rows, diag = self.parse(common_start() + [event("event_msg", {"type": "task_complete", "turn_id": "turn-1"})])
        self.assertEqual(len(rows), 1)
        self.assertEqual(diag["request_usage_missing"], 1)

    def test_malformed_jsonl_line_is_skipped(self):
        lines = common_start() + ["{not valid json", token(usage(10, 0, 2)), event("event_msg", {"type": "task_complete", "turn_id": "turn-1"})]
        rows, diag = self.parse(lines)
        self.assertEqual(len(rows), 1)
        self.assertEqual(diag["parse_errors"], 1)

    def test_archived_sessions_are_discovered(self):
        home = self.root / "codex"
        lines = common_start() + [token(usage(10, 0, 2)), event("event_msg", {"type": "task_complete", "turn_id": "turn-1"})]
        write_lines(home / "archived_sessions" / "rollout-archived.jsonl", lines)
        found = list(dashboard.iter_rollout_files(home, include_archived=True))
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0][1])
        rows, _ = dashboard.parse_rollout(found[0][0], archived=found[0][1])
        self.assertTrue(rows[0]["archived"])

    def test_incremental_file_update_only_reparses_changed_file(self):
        home = self.root / "codex"
        path = home / "sessions" / "rollout-live.jsonl"
        first = common_start() + [token(usage(10, 0, 2)), event("event_msg", {"type": "task_complete", "turn_id": "turn-1"})]
        write_lines(path, first)
        index = dashboard.SessionIndex({**dashboard.DEFAULT_CONFIG, "codex_home": str(home)}, self.root / "imports")
        rows, diag = index.refresh()
        self.assertEqual((len(rows), diag["files_reparsed_this_scan"]), (1, 1))
        _, diag = index.refresh()
        self.assertEqual((diag["cache_hits_this_scan"], diag["files_reparsed_this_scan"]), (1, 0))
        second = [
            event("event_msg", {"type": "task_started", "turn_id": "turn-2"}),
            event("event_msg", {"type": "user_message", "message": "Run tests"}),
            token(usage(20, 0, 4), usage(10, 0, 2)),
            event("event_msg", {"type": "task_complete", "turn_id": "turn-2"}),
        ]
        with path.open("a", encoding="utf-8") as stream:
            stream.write("\n".join(second) + "\n")
        rows, diag = index.refresh()
        self.assertEqual((len(rows), diag["files_reparsed_this_scan"]), (2, 1))

    def test_credit_estimate_does_not_double_count_cache_or_reasoning(self):
        config = {"rates": {"default": {"input": 100, "cached": 10, "cache_write": 100, "output": 500}}}
        value = dashboard.estimate_credits("unknown", {
            "input_tokens": 100, "cached_input_tokens": 40, "cache_write_input_tokens": 0,
            "output_tokens": 20, "reasoning_output_tokens": 5,
        }, config)
        self.assertEqual(value, 0.0164)


if __name__ == "__main__":
    unittest.main()
