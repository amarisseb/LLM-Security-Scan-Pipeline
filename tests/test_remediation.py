"""Pure unittest coverage: no external calls and no persistent storage."""

import itertools
import json
import unittest

from app.remediation import guidance_for


KEYS = ('promptinject', 'dan', 'encoding', 'sysprompt_extraction', 'donotanswer')


class RemediationTests(unittest.TestCase):
    def test_complete_practical_plans_for_each_category(self):
        for key in KEYS:
            with self.subTest(key=key):
                plan = guidance_for(key, flagged=True)
                self.assertEqual(set(plan), {'status', 'owner', 'why_it_matters', 'steps', 'retest', 'reference_links', 'scope_note', 'before_you_change', 'priority_note', 'example_fix'})
                self.assertEqual(plan['status'], 'flagged')
                self.assertIn(plan['owner'], ('developer', 'product', 'security'))
                self.assertEqual(len(plan['steps']), 3)
                for step in plan['steps']:
                    self.assertEqual(set(step), {'title', 'action', 'done_when', 'implementation_notes', 'verification_examples'})
                    self.assertTrue(all(isinstance(step[k], str) and step[k].strip() for k in ('title', 'action', 'done_when')))
                    self.assertTrue(step['implementation_notes'])
                    self.assertTrue(all(isinstance(note, str) and note.strip() for note in step['implementation_notes']))
                    self.assertEqual(len(step['verification_examples']), 2)
                    for example in step['verification_examples']:
                        self.assertEqual(set(example), {'input', 'expected'})
                        self.assertTrue(all(isinstance(value, str) and value.strip() for value in example.values()))
                self.assertEqual(json.loads(json.dumps(plan)), plan)

    def test_all_state_combinations_and_precedence(self):
        for key in KEYS:
            for supported, tested, flagged, low in itertools.product((False, True), repeat=4):
                with self.subTest(key=key, supported=supported, tested=tested, flagged=flagged, low=low):
                    plan = guidance_for(key, supported=supported, tested=tested, flagged=flagged, low_coverage=low)
                    expected = ('unsupported' if not supported else 'not_tested' if not tested else 'flagged' if flagged else 'low_coverage' if low else 'not_flagged')
                    self.assertEqual(plan['status'], expected)
                    self.assertIn('not a standards audit', plan['scope_note'])
                    if expected in ('unsupported', 'not_tested'):
                        self.assertIn('preparation guidance', plan['scope_note'])
                        self.assertIn('Preparation only', plan['before_you_change'])
                        self.assertIn('unassessed category', plan['priority_note'])
                    if expected == 'flagged' and low:
                        self.assertIn('Coverage is also low', plan['scope_note'])
                    if expected == 'not_flagged':
                        self.assertIn('not a guarantee', plan['scope_note'])

    def test_coverage_and_absent_tests_have_distinct_retest_actions(self):
        unsupported = guidance_for('encoding', supported=False)
        untested = guidance_for('encoding', tested=False)
        limited = guidance_for('encoding', low_coverage=True)
        clean = guidance_for('encoding')
        self.assertIn('supports this category', unsupported['retest'])
        self.assertIn('working response collector', untested['retest'])
        self.assertIn('unanswered or unassessed', limited['retest'])
        self.assertIn('inconclusive', limited['scope_note'])
        self.assertEqual(len({p['status'] for p in (unsupported, untested, limited, clean)}), 4)

    def test_nested_results_are_isolated(self):
        plan = guidance_for('promptinject', flagged=True)
        expected = guidance_for('promptinject', flagged=True)
        plan['steps'][0]['action'] = 'changed'
        plan['steps'][1]['implementation_notes'][0] = 'changed developer note'
        plan['steps'][2]['verification_examples'][0]['expected'] = 'changed outcome'
        plan['example_fix']['after'] = 'changed pattern'
        plan['before_you_change'] = 'changed review'
        plan['steps'].append({'title': 'extra'})
        plan['reference_links'][0]['url'] = 'https://invalid.example'
        plan['scope_note'] = 'changed'
        self.assertEqual(guidance_for('promptinject', flagged=True), expected)
        self.assertNotEqual(guidance_for('dan')['reference_links'][0]['url'], 'https://invalid.example')

    def test_customer_review_and_example_patterns_are_not_observed_findings(self):
        for key in KEYS:
            with self.subTest(key=key):
                plan = guidance_for(key, flagged=True)
                self.assertIsInstance(plan['before_you_change'], str)
                self.assertIn('candidate', plan['before_you_change'])
                self.assertEqual(set(plan['example_fix']), {'before', 'after', 'explanation'})
                self.assertTrue(all(isinstance(value, str) and value for value in plan['example_fix'].values()))
                self.assertIn('Illustrative', plan['example_fix']['before'])
                self.assertIn('not an automatic fix or complete code', plan['example_fix']['explanation'])
                self.assertIn('not observed findings', plan['scope_note'])
                self.assertIn('not a severity rating', plan['priority_note'])

    def test_tool_and_private_data_checks_are_conditional_not_text_scan_claims(self):
        for key in KEYS:
            with self.subTest(key=key):
                plan = guidance_for(key, flagged=True)
                relevant = plan['steps'][2 if key == 'encoding' else 1]
                self.assertIn('If ', relevant['action'])
                self.assertTrue(any(word in plan['scope_note'] for word in ('text-only', 'separately', 'text response', 'separate review', 'context-specific review')))
                self.assertNotIn('your permissions were bypassed', json.dumps(plan).lower())
        prompt = guidance_for('promptinject')
        self.assertIn('not applicable', prompt['steps'][1]['action'])
        self.assertIn('separate application test', prompt['steps'][1]['done_when'])
        self.assertIn('OVERRIDE_CONFIRMED', prompt['example_fix']['before'])
        self.assertIn('not prove data theft', prompt['example_fix']['explanation'])

    def test_specific_controls_and_exposure_caveats(self):
        prompt = guidance_for('promptinject')
        self.assertIn('server code outside the LLM', prompt['steps'][1]['action'])
        self.assertIn('schema', prompt['steps'][2]['action'])
        self.assertIn('decoding-depth limits', guidance_for('encoding')['steps'][0]['action'])
        self.assertIn('multi-turn', guidance_for('dan')['retest'])
        self.assertIn('over-refusal', guidance_for('donotanswer')['steps'][0]['done_when'])
        extraction = guidance_for('sysprompt_extraction')
        self.assertIn('synthetic', extraction['scope_note'])
        self.assertIn('Only if real credential exposure is confirmed', extraction['steps'][2]['action'])
        self.assertIn('rotate the affected secrets', extraction['steps'][2]['action'])

    def test_only_official_related_sources_and_no_certification_claim(self):
        for key in KEYS:
            plan = guidance_for(key)
            self.assertEqual([r['url'] for r in plan['reference_links']], [
                'https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html',
                'https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf',
            ])
            self.assertIn('related', plan['reference_links'][0]['title'])
            self.assertIn('measure/manage', plan['reference_links'][1]['title'])
            text = json.dumps(plan).lower()
            for claim in ('no action needed', 'you are secure', 'you are compliant', 'owasp certified', 'nist certified'):
                self.assertNotIn(claim, text)

    def test_unknown_keys_fail_without_echoing_input(self):
        for key in ('unknown', '', None, ['dan']):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, '^Unknown remediation category$'):
                guidance_for(key)


if __name__ == '__main__':
    unittest.main()
