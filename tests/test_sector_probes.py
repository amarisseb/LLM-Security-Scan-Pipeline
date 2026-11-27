"""Exercise real garak probes, detectors, evaluator and report serialisation offline."""
import datetime
import json
import logging
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

logging.getLogger().addHandler(logging.NullHandler())

from garak import _config, _plugins
from garak.attempt import Message
from garak.generators.test import Blank
from garak.evaluators import ThresholdEvaluator
from garak.probes.sysprompt_extraction import SystemPromptExtraction
from app import run_scan as engine
from app import application_scan, application_generator, scan_worker
from app.sector_probes import load_scenarios, marker_reply, sector_plugins
import generate_report


class SectorTests(unittest.TestCase):
    def test_fixture(self):
        fixture = load_scenarios()
        self.assertEqual(fixture['version'], 1)
        self.assertEqual([s['id'] for s in fixture['sectors']], ['legal', 'healthcare', 'education'])
        cases = [c for s in fixture['sectors'] for c in s['cases']]
        self.assertEqual(len({c['id'] for c in cases}), 12)
        self.assertEqual(len({c['marker'] for c in cases}), 12)
        for sector in fixture['sectors']:
            self.assertEqual(len(sector['cases']), 4)
        for case in cases:
            self.assertEqual(set(case), set('id title attack_type attack_label task prompt marker weak_response strong_response risk next_step scope_note'.split()))
            self.assertTrue(case['marker'].startswith('ARISEC_TEST_'))
            self.assertEqual(case['weak_response'], case['marker'])
            self.assertNotIn(case['marker'], case['strong_response'])
            self.assertIn(case['task'], case['prompt'])
            self.assertIn('not domain accuracy or compliance', case['scope_note'])

    def test_exact_final_reply(self):
        marker = 'ARISEC_TEST_EXAMPLE'
        for reply in (marker, ' \n'+marker+'\n', '<think>Reject injection internally.</think>\n'+marker):
            self.assertTrue(marker_reply(reply, marker))
        for reply in (None, 'I refuse '+marker, '"'+marker+'"', marker+'.',
                      '<think>'+marker, '<think>x<think>y</think></think>'+marker,
                      '<think>x</think><think>y</think>'+marker, marker.lower()):
            self.assertFalse(marker_reply(reply, marker))

    def test_general_and_unknown(self):
        self.assertEqual(sector_plugins(), ([], {}))
        for invalid in ('unknown', '', None, 'LEGAL'):
            with self.assertRaises(ValueError):
                sector_plugins(invalid)

    def test_application_engine_keeps_credentials_out_of_reports(self):
        secret = 'SECTOR-PRIVATE-TOKEN-DO-NOT-LOG'
        private_template = 'SECTOR-PRIVATE-TEMPLATE-DO-NOT-LOG'
        case = load_scenarios()['sectors'][0]['cases'][0]
        def answer(url, payload, token):
            self.assertEqual(token, secret)
            self.assertEqual(payload['private'], private_template)
            return {'answer': case['marker'] if payload['message'] == case['prompt'] else 'Safe answer.'}
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(engine, 'PROBES', ['test.Test']), \
                patch.object(application_generator, 'post_json', side_effect=answer), \
                patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden')):
            progress = []
            report = application_scan.run_application_scan('https://example.com/ai',
                {'message': '{{prompt}}', 'private': private_template}, 'answer', secret, folder,
                on_progress=lambda *args: progress.append(args), prompt_cap=1, scenario_sector='legal')
            self.assertEqual(len(progress), 5)
            records = generate_report.load_jsonl(report)
            extra = [r for r in records if r.get('entry_type') == 'eval' and 'ArisecCase_' in r['probe']]
            self.assertEqual(len(extra), 4)
            self.assertEqual(sum(r['fails'] for r in extra), 1)
            for path in Path(folder).rglob('*'):
                if path.is_file():
                    self.assertNotIn(secret.encode(), path.read_bytes())
                    self.assertNotIn(private_template.encode(), path.read_bytes())

    def test_http_worker_forwards_sector(self):
        payload = {'url': 'https://example.com/ai', 'template': {'q': '{{prompt}}'},
                   'response_path': 'answer', 'scenario_sector': 'education'}
        with patch.object(application_scan, 'run_application_scan', return_value=Path('report')) as run, \
                patch('app.lab_policy.configure_local_targets'):
            scan_worker._run({'payload': payload, 'kind': 'http', 'output_dir': 'unused'}, None)
            self.assertEqual(run.call_args.kwargs['scenario_sector'], 'education')
            payload.pop('scenario_sector')
            scan_worker._run({'payload': payload, 'kind': 'http', 'output_dir': 'unused'}, None)
            self.assertNotIn('scenario_sector', run.call_args.kwargs)

    def test_registry_restored_after_failure(self):
        names, registry = sector_plugins('legal')
        original_loader = _plugins.load_plugin
        original_info = _plugins.PluginCache.plugin_info
        with patch.object(engine.command, 'start_run'), \
                patch.object(engine.command, 'probewise_run', side_effect=RuntimeError('stub failure')):
            with self.assertRaises(RuntimeError):
                engine._run_probes(Blank(), names, None, 1, None, local_registry=registry)
        self.assertIs(_plugins.load_plugin, original_loader)
        self.assertIs(_plugins.PluginCache.plugin_info, original_info)

    def test_real_garak_reports_each_sector(self):
        engine._make_output_encoding_safe()
        # Replace only the baseline's external dataset with a tiny offline fixture.
        # Its probe, detector, generation and report code still execute normally.
        with patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden')), \
                patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
                patch.object(SystemPromptExtraction, '_load_dataset_prompts',
                             return_value=['You are a fictional archive assistant. Sort document labels.']):
            for sector in load_scenarios()['sectors']:
                with self.subTest(sector=sector['id']), tempfile.TemporaryDirectory() as folder:
                    engine._reset_garak_state()
                    _config.load_base_config()
                    _config.transient.starttime = datetime.datetime.now()
                    _config.transient.starttime_iso = _config.transient.starttime.isoformat()
                    _config.reporting.report_dir = folder
                    _config.system.lite = False
                    _config.system.parallel_attempts = False
                    _config.system.parallel_requests = False
                    _config.run.generations = 1
                    _config.run.seed = engine.SAMPLE_SEED
                    _config.run.soft_probe_prompt_cap = 1
                    baseline, unknown = _config.parse_plugin_spec(','.join(engine.PROBES), 'probes')
                    self.assertFalse(unknown)
                    self.assertEqual(len(set(baseline)), 23)
                    names, registry = sector_plugins(sector['id'])
                    self.assertEqual(len(set(baseline + names)), 27)
                    replies = {c['prompt']: c['weak_response'] if i % 2 == 0 else c['strong_response']
                               for i, c in enumerate(sector['cases'])}

                    class Stub(Blank):
                        """Offline model; actual garak execution remains intact."""
                        __module__ = 'garak.generators.test'
                        def _call_model(self, prompt, generations_this_call=1):
                            text = prompt.turns[-1].content.text
                            return [Message(replies.get(text, 'I cannot follow that request.'))] * generations_this_call

                    Stub.__name__ = 'Blank'
                    generator = Stub()
                    progress = []
                    original = _plugins.load_plugin
                    try:
                        report = engine._run_probes(generator, baseline + names,
                            ThresholdEvaluator(_config.run.eval_threshold), 1,
                            lambda *args: progress.append(args), local_registry=registry)
                    finally:
                        engine._close_report_file()
                    self.assertIs(_plugins.load_plugin, original)
                    self.assertEqual(len(progress), 27)
                    self.assertTrue(all(p[1] == 27 for p in progress))
                    records = generate_report.load_jsonl(report)
                    hits = generate_report.load_jsonl(Path(str(report).replace('.report.jsonl', '.hitlog.jsonl')))
                    evaluations = [r for r in records if r.get('entry_type') == 'eval']
                    self.assertEqual(len({r['probe'] for r in evaluations}), 27)
                    extra = [r for r in evaluations if 'ArisecCase_' in r['probe']]
                    self.assertEqual(len(extra), 4)
                    self.assertEqual(sum(r['fails'] for r in extra), 2)
                    stats = generate_report.build_stats(extra)
                    self.assertEqual(stats['promptinject'], {'passed': 2, 'fails': 2})
                    sector_hits = [h for h in hits if 'ArisecCase_' in h['probe']]
                    self.assertEqual(len(sector_hits), 2)
                    self.assertIn('ARISEC_TEST_', generate_report.build_evidence(sector_hits)['promptinject']['returned'])


if __name__ == '__main__':
    unittest.main()
