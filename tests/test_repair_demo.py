import unittest
from unittest.mock import patch

from app.repair_demo import read_after, run_example


class RepairDemoTests(unittest.TestCase):
    def test_attack_does_not_run_correction_or_retest(self):
        with patch('app.repair_demo.read_after') as corrected:
            result = run_example('attack')
        corrected.assert_not_called()
        self.assertIsNone(result['after'])
        self.assertTrue(result['before']['unauthorised_disclosure'])

    def test_retest_executes_corrected_attack_and_normal_access(self):
        result = run_example('retest')
        self.assertTrue(result['after']['attack_blocked'])
        self.assertTrue(result['after']['normal_use_passed'])

    def test_attack_and_ordinary_use_replayed(self):
        result = run_example()
        self.assertTrue(result['before']['unauthorised_disclosure'])
        self.assertTrue(result['after']['attack_blocked'])
        self.assertTrue(result['after']['normal_use_passed'])
        self.assertIn('+    if user["organisation_id"]', result['fix']['diff'])
        self.assertEqual(result['kind'], 'deterministic_permission_demo')

    def test_permission_check_does_not_mutate_records(self):
        record = {'organisation_id': 'private', 'text': 'test'}
        with self.assertRaises(PermissionError):
            read_after({'organisation_id': 'other'}, record)
        self.assertEqual(record, {'organisation_id': 'private', 'text': 'test'})

    def test_missing_identity_fails_closed(self):
        with self.assertRaises(KeyError):
            read_after({}, {'organisation_id': 'private', 'text': 'test'})

    def test_repeatable_no_shared_state(self):
        changed = run_example()
        changed['after']['attack_blocked'] = False
        self.assertTrue(run_example()['after']['attack_blocked'])
