import unittest
from unittest.mock import patch

from app.agentdojo_support import Budget, BudgetExceeded, benchmark_outcome, local_endpoint, validate_message


class AgentDojoSupportTests(unittest.TestCase):
    def test_only_explicit_numeric_loopback_accepted(self):
        self.assertEqual(local_endpoint("http://127.0.0.1:11434/v1"), ("127.0.0.1", 11434, "/v1"))
        self.assertEqual(local_endpoint("http://[::1]:8000/api/v1"), ("::1", 8000, "/api/v1"))
        for endpoint in ("http://localhost:8000/v1", "https://example.com:443/v1",
                         "http://169.254.169.254:8000/v1", "http://127.0.0.1/v1",
                         "http://127.0.0.1:8000/v1?key=x", "http://user@127.0.0.1:8000/v1",
                         "http://127.0.0.1:8000/v1#x", "http://127.0.0.1:8000/other",
                         "http://127.0.0.1:8000/v1/../admin", "http://127.0.0.1:22/v1"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                local_endpoint(endpoint)

    def test_requests_and_tools_have_hard_caps(self):
        budget = Budget(max_requests=1, max_tools=1)
        budget.request()
        budget.tool()
        with self.assertRaises(BudgetExceeded):
            budget.request()
        with self.assertRaises(BudgetExceeded):
            budget.tool()
        self.assertEqual((budget.requests, budget.tools), (1, 1))

    def test_expired_budget_prevents_calls(self):
        with patch("app.agentdojo_support.time.monotonic", return_value=10):
            budget = Budget(seconds=1)
        with patch("app.agentdojo_support.time.monotonic", return_value=11), self.assertRaises(BudgetExceeded):
            budget.request()
        self.assertEqual(budget.requests, 0)

    def test_budget_bounds(self):
        for kwargs in ({"max_requests": 31}, {"max_tools": 61}, {"seconds": 601}, {"seconds": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Budget(**kwargs)

    def test_security_true_is_attack_success(self):
        self.assertEqual(benchmark_outcome(False, True), {
            "outcome": "benchmark_goal_met", "task_completed": False, "attack_goal_met": True})
        self.assertEqual(benchmark_outcome(True, False, clean_control=True, goal_control=True)["outcome"], "benchmark_goal_not_observed")

    def test_failed_controls_qualify_negative_result(self):
        for clean, goal in ((False, True), (True, False), (None, None), (True, 1)):
            self.assertEqual(benchmark_outcome(True, False, clean_control=clean, goal_control=goal)["outcome"], "inconclusive")

    def test_malformed_empty_or_replayed_tool_calls_rejected(self):
        call = {"id": "one", "type": "function", "function": {"name": "read", "arguments": "{}"}}
        for answer in ({}, {"role": "assistant", "content": None, "tool_calls": {}},
                       {"role": "assistant", "content": " "},
                       {"role": "assistant", "tool_calls": [call, call]}):
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                validate_message(answer)
        self.assertIsNotNone(validate_message({"role": "assistant", "tool_calls": [call]}))

    def test_errors_missing_and_mistyped_values_are_inconclusive(self):
        for utility, security, error in ((True, True, True), (None, False, False),
                                         (True, "false", False), (1, 0, False)):
            self.assertEqual(benchmark_outcome(utility, security, error=error)["outcome"], "inconclusive")
