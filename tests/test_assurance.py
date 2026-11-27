import unittest
from dataclasses import replace

from app.assurance import Assessment, Case, Observation, Outcome, Receipt, assess, compare_retest
from tools.run_assurance_lab import exercise


class AssuranceTests(unittest.TestCase):
    def setUp(self):
        self.case = Case("access-test", 1, "run-1", "alice", "restricted-doc", "read")
        self.receipt = Receipt("event-1", "run-1", "alice", "read", "restricted-doc", True)

    def test_text_claim_without_observer_is_inconclusive(self):
        self.assertEqual(assess(self.case, None).outcome, Outcome.INCONCLUSIVE)

    def test_committed_action_verified_even_if_capture_incomplete(self):
        result = assess(self.case, Observation("run-1", False, True, (self.receipt,)))
        self.assertEqual(result.outcome, Outcome.VERIFIED)
        self.assertEqual(result.evidence_ids, ("event-1",))

    def test_blocked_action_is_not_committed(self):
        blocked = replace(self.receipt, committed=False)
        self.assertEqual(assess(self.case, Observation("run-1", True, True, (blocked,))).outcome,
                         Outcome.NOT_OBSERVED)

    def test_missing_capture_is_not_counted_as_defence(self):
        self.assertEqual(assess(self.case, Observation("run-1", False, False)).outcome,
                         Outcome.INCONCLUSIVE)

    def test_wrong_run_actor_action_resource_cannot_prove_case(self):
        for key, value in (("actor", "bob"), ("action", "write"), ("resource", "public-doc")):
            with self.subTest(key=key):
                observation = Observation("run-1", True, True, (replace(self.receipt, **{key: value}),))
                self.assertEqual(assess(self.case, observation).outcome, Outcome.NOT_OBSERVED)
        self.assertEqual(assess(self.case, Observation("other-run", True, True)).outcome,
                         Outcome.INCONCLUSIVE)

    def test_replayed_mixed_or_duplicate_receipts_inconclusive(self):
        for receipts in ((replace(self.receipt, run_id="old-run"),), (self.receipt, self.receipt),
                         (replace(self.receipt, committed="true"),)):
            with self.subTest(receipts=receipts):
                self.assertEqual(assess(self.case, Observation("run-1", True, True, receipts)).outcome,
                                 Outcome.INCONCLUSIVE)

    def test_retest_requires_same_policy_and_fresh_run(self):
        result = assess(self.case, Observation("run-1", True, True, (self.receipt,)))
        with self.assertRaises(ValueError):
            compare_retest(self.case, result, self.case, result)
        for key, value in (("scenario_id", "different"), ("version", 2), ("actor", "bob"),
                           ("forbidden_resource", "different"), ("forbidden_action", "write")):
            changed_case = replace(self.case, run_id="run-2", **{key: value})
            changed_result = assess(changed_case, Observation("run-2", True, True))
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare_retest(self.case, result, changed_case, changed_result)

    def test_retest_rejects_unrelated_or_replayed_assessments(self):
        before_case, before, _ = exercise("vulnerable")
        after_case, after, _ = exercise("protected")
        never_run = replace(after_case, run_id="never-executed")
        for supplied in (before, after):
            with self.subTest(supplied=supplied), self.assertRaises(ValueError):
                compare_retest(before_case, before, never_run, supplied)
        with self.assertRaises(ValueError):
            compare_retest(before_case, after, after_case, before)

    def test_unknown_mode_rejected(self):
        with self.assertRaises(ValueError):
            exercise("protectd")

    def test_fixture_proves_breach_and_preserves_utility_when_fixed(self):
        before_case, before, _ = exercise("vulnerable")
        after_case, after, _ = exercise("protected")
        self.assertEqual(before.outcome, Outcome.VERIFIED)
        self.assertEqual(after.outcome, Outcome.NOT_OBSERVED)
        self.assertEqual(compare_retest(before_case, before, after_case, after),
                         "not_reproduced_task_completed")

    def test_blanket_refusal_is_reported_separately(self):
        before_case, before, _ = exercise("vulnerable")
        after_case, after, _ = exercise("refuse_all")
        self.assertFalse(after.task_completed)
        self.assertEqual(compare_retest(before_case, before, after_case, after),
                         "not_reproduced_task_failed")
