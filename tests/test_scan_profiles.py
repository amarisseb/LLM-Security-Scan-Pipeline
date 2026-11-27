"""Strict server profiles select real garak families, independently of prompt caps."""
from contextlib import ExitStack
import json
import logging
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

logging.getLogger().addHandler(logging.NullHandler())

from garak import _config, _plugins
from garak.generators.test import Blank
from garak.probes.sysprompt_extraction import SystemPromptExtraction
from app import run_scan as engine
from app import application_scan, provider_generator, scan_worker

FULL_FAMILIES = {'promptinject', 'dan', 'encoding', 'sysprompt_extraction', 'donotanswer'}


class ScanProfileTests(unittest.TestCase):
    def setUp(self):
        engine._make_output_encoding_safe()
        engine._reset_garak_state()
        _config.load_base_config()

    def test_allowlist_and_no_arbitrary_specs(self):
        self.assertEqual(engine.profile_probes(), engine.PROBES)
        self.assertEqual(engine.profile_probes('free'), ['promptinject'])
        for invalid in ('', 'FREE', 'Full', ' free', 'promptinject', 'all', 'free,dan',
                        None, True, 1, [], {}, ['free']):
            with self.subTest(profile=invalid):
                with self.assertRaisesRegex(ValueError, 'Unknown scan profile'):
                    engine.profile_probes(invalid)

    def test_unknown_profile_fails_before_any_generator_or_output(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            browser = stack.enter_context(patch.object(engine._plugins, 'load_plugin'))
            provider = stack.enter_context(patch.object(provider_generator, 'ProviderGenerator'))
            application = stack.enter_context(patch.object(application_scan, 'ApplicationGenerator'))
            path = Path(folder)/'must-not-exist'
            calls = [
                lambda: engine.run_scan('https://example.invalid', path, scan_profile='all'),
                lambda: engine._run_scan('https://example.invalid', path, 1, 1, {}, None, True, scan_profile=[]),
                lambda: engine.run_api_scan('openai', 'gpt-4o-mini', 'fake-key', path, scan_profile=None),
                lambda: engine._run_api_scan('openai', 'gpt-4o-mini', 'fake-key', path, 1, 1, None, scan_profile=''),
                lambda: application_scan.run_application_scan('https://example.invalid', {'q':'{{prompt}}'},
                    'answer', '', path, scan_profile='dan'),
            ]
            for call in calls:
                with self.assertRaises(ValueError):
                    call()
            self.assertFalse(path.exists())
            browser.assert_not_called()
            provider.assert_not_called()
            application.assert_not_called()

    def test_free_rejects_sector_extras_before_output(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(application_scan, 'ApplicationGenerator') as generator:
            path = Path(folder)/'must-not-exist'
            for sector in ('legal', 'healthcare', 'education', '', None):
                with self.assertRaises(ValueError):
                    application_scan.run_application_scan('https://example.invalid', {'q':'{{prompt}}'},
                        'answer', '', path, scan_profile='free', scenario_sector=sector)
            self.assertFalse(path.exists())
            generator.assert_not_called()

    def test_default_wrapper_calls_remain_compatible(self):
        with patch.object(engine, '_run_scan', return_value=Path('report')) as run:
            engine.run_scan('https://example.invalid', 'out')
            self.assertEqual(run.call_args.kwargs, {})
            engine.run_scan('https://example.invalid', 'out', scan_profile='free')
            self.assertEqual(run.call_args.kwargs, {'scan_profile':'free'})
        with patch.object(engine, '_run_api_scan', return_value=Path('report')) as run:
            engine.run_api_scan('openai', 'gpt-4o-mini', 'fake-key', 'out')
            self.assertEqual(run.call_args.kwargs, {})
            engine.run_api_scan('openai', 'gpt-4o-mini', 'fake-key', 'out', scan_profile='free')
            self.assertEqual(run.call_args.kwargs, {'scan_profile':'free'})

    def test_worker_explicit_profiles_and_legacy_defaults(self):
        payloads = {
            'http': {'url':'https://example.invalid', 'template':{'q':'{{prompt}}'}, 'response_path':'answer'},
            'api': {'provider':'openai', 'model':'gpt-4o-mini', 'api_key':'fake-key'},
            'web': {'target_url':'https://example.invalid'},
        }
        for kind, payload in payloads.items():
            for profile in (None, 'full', 'free'):
                job_payload = dict(payload)
                if profile is not None:
                    job_payload['scan_profile'] = profile
                with patch.object(application_scan, 'run_application_scan') as http, \
                        patch.object(engine, 'run_api_scan') as api, \
                        patch.object(engine, 'run_scan') as web, \
                        patch('app.lab_policy.configure_local_targets'):
                    scan_worker._run({'kind':kind, 'payload':job_payload, 'output_dir':'out'}, None)
                    called = {'http':http,'api':api,'web':web}[kind]
                    if profile is None:
                        self.assertNotIn('scan_profile', called.call_args.kwargs)
                    else:
                        self.assertEqual(called.call_args.kwargs['scan_profile'], profile)

    def test_worker_rejects_invalid_profiles_and_free_sector(self):
        with patch.object(application_scan, 'run_application_scan') as run, \
                patch('app.lab_policy.configure_local_targets'):
            for payload in ({'scan_profile':'all'}, {'scan_profile':[]},
                            {'scan_profile':'free','scenario_sector':'legal'}):
                with self.assertRaises(ValueError):
                    scan_worker._run({'kind':'http','payload':payload,'output_dir':'unused'}, None)
            run.assert_not_called()

    def test_scripted_demo_dispatch_is_internal_and_exact_boolean(self):
        demo = Mock(return_value=Path('demo.report.jsonl'))
        payload = {'scripted_demo':True, 'scan_profile':'free', 'prompt_cap':2}
        progress = Mock()
        with patch.dict(sys.modules, {'app.demo_scan':SimpleNamespace(run_demo_scan=demo)}), \
                patch.object(application_scan, 'run_application_scan') as http, \
                patch('app.lab_policy.configure_local_targets'):
            result = scan_worker._run({'kind':'http','payload':payload,'output_dir':'out'}, progress)
            self.assertEqual(result, Path('demo.report.jsonl'))
            demo.assert_called_once_with(Path('out'), prompt_cap=1, scan_profile='free', on_progress=progress)
            http.assert_not_called()
            demo.reset_mock()
            payload.update(scripted_demo='true', url='https://example.invalid',
                           template={'q':'{{prompt}}'}, response_path='answer')
            scan_worker._run({'kind':'http','payload':payload,'output_dir':'out'}, progress)
            demo.assert_not_called()
            http.assert_called_once()

    def test_actual_garak_reports_select_families_and_respect_caps(self):
        # Stub only target generation and the baseline's downloaded dataset.
        # The real probes, detectors, caps, harness and JSONL writer execute.
        for kind in ('http', 'api', 'web'):
            for profile, cap in (('free', 1), ('free', 2), ('full', 1)):
                with self.subTest(kind=kind,profile=profile,cap=cap), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                    stack.enter_context(patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden')))
                    stack.enter_context(patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')))
                    stack.enter_context(patch.object(SystemPromptExtraction, '_load_dataset_prompts',
                        return_value=['You are a fictional archive assistant. Sort document labels.']))
                    generator = Blank()
                    generator.close = Mock()
                    generator.check_deadline = Mock()
                    generator.preflight = Mock()
                    generator.responds_like_ai = Mock(return_value=True)
                    progress = []
                    callback = lambda *args: progress.append(args)
                    if kind == 'http':
                        stack.enter_context(patch.object(application_scan, 'ApplicationGenerator', return_value=generator))
                        report = application_scan.run_application_scan('https://example.invalid', {'q':'{{prompt}}'},
                            'answer', '', folder, prompt_cap=cap, scan_profile=profile, on_progress=callback)
                    elif kind == 'api':
                        stack.enter_context(patch.object(provider_generator, 'ProviderGenerator', return_value=generator))
                        report = engine.run_api_scan('openai', 'gpt-4o-mini', 'fake-key', folder,
                            prompt_cap=cap, scan_profile=profile, on_progress=callback)
                    else:
                        original = _plugins.load_plugin
                        def load(path, *args, **kwargs):
                            return generator if path == 'generators.browser' else original(path, *args, **kwargs)
                        stack.enter_context(patch.object(_plugins, 'load_plugin', side_effect=load))
                        report = engine.run_scan('https://example.invalid', folder,
                            prompt_cap=cap, scan_profile=profile, on_progress=callback)
                    generator.close.assert_called_once()
                    rows = [json.loads(line) for line in report.read_text(encoding='utf-8').splitlines()]
                    setup = rows[0]
                    self.assertEqual(setup['run.scan_profile'], profile)
                    self.assertEqual(setup['plugins.probe_spec'], ','.join(engine.profile_probes(profile)))
                    self.assertEqual(setup['run.soft_probe_prompt_cap'], cap)
                    evaluations = [r for r in rows if r.get('entry_type') == 'eval']
                    families = {r['probe'].split('.')[0] for r in evaluations}
                    self.assertEqual(families, {'promptinject'} if profile == 'free' else FULL_FAMILIES)
                    expected = 3 if profile == 'free' else 23
                    self.assertEqual(len({r['probe'] for r in evaluations}), expected)
                    self.assertEqual(len(progress), expected)
                    self.assertTrue(all(total == expected for _,total,_ in progress))
                    attempts = [r for r in rows if r.get('entry_type') == 'attempt' and r.get('status') == 2]
                    self.assertEqual(len(attempts), expected*cap)
                    self.assertIn('completion', {r['entry_type'] for r in rows})


if __name__ == '__main__':
    unittest.main()
