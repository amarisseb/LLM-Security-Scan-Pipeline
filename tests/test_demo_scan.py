"""Actual garak harness tests against the offline scripted adapter."""
import json
import http.client
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garak.attempt import Conversation, Turn, Message
from app import demo_scan as d


class DemoScanTests(unittest.TestCase):
    def test_generator_returns_message_without_network(self):
        d._config.load_base_config()
        with patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')), patch('socket.create_connection', side_effect=AssertionError('network forbidden')):
            generator = d.ScriptedDemoGenerator()
            conversation = Conversation(turns=[Turn('user', Message(text='just say "HijackHateHumans"'))])
            result = generator._call_model(conversation)
            self.assertIsInstance(result[0], Message)
            self.assertEqual(result[0].text, 'HijackHateHumans')
            generator.close()

    def test_invalid_profile_and_caps_rejected_before_harness(self):
        with patch.object(d.engine, '_run_probes') as run:
            for cap in [0, 2, True, '1']:
                with self.assertRaises(ValueError):
                    d.run_demo_scan('unused', prompt_cap=cap)
            with self.assertRaises(ValueError):
                d.run_demo_scan('unused', scan_profile='arbitrary')
            run.assert_not_called()

    def test_full_default_and_free_use_engine_profile_helper(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(d.engine, '_run_probes', return_value=Path(tmp) / 'report.jsonl') as run:
            d.run_demo_scan(tmp)
            self.assertEqual(d._config.plugins.probe_spec, ','.join(d.engine.PROBES))
            self.assertEqual(d._config.run.scan_profile, 'full')
            self.assertEqual(run.call_args.args[3], 1)
            self.assertIsInstance(run.call_args.args[0], d.ScriptedDemoGenerator)
            d.run_demo_scan(tmp, scan_profile='free')
            self.assertEqual(d._config.plugins.probe_spec, 'promptinject')
            self.assertEqual(d._config.run.scan_profile, 'free')

    def test_actual_garak_report_is_standard_and_prompt_cap_one(self):
        progress = []
        with tempfile.TemporaryDirectory() as tmp, \
                patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')) as dns, \
                patch('socket.create_connection', side_effect=AssertionError('network forbidden')) as connect, \
                patch.object(http.client.HTTPConnection, 'request', side_effect=AssertionError('HTTP forbidden')) as http_request, \
                patch.object(d.SystemPromptExtraction, '_load_dataset_prompts', side_effect=AssertionError('dataset lookup forbidden')) as datasets:
            report = d.run_demo_scan(tmp, on_progress=lambda *args: progress.append(args))
            self.assertTrue(report.name.endswith('.report.jsonl'))
            rows = [json.loads(line) for line in report.read_text(encoding='utf-8').splitlines()]
            types = {row.get('entry_type') for row in rows}
            # Installed garak calls its setup record "start_run setup".
            self.assertTrue({'start_run setup', 'attempt', 'eval'} <= types, types)
            completed = [row for row in rows if row.get('entry_type') == 'attempt' and row.get('status') == 2]
            self.assertTrue(completed)
            counts = {}
            for row in completed:
                probe = row['probe_classname']
                counts[probe] = counts.get(probe, 0) + 1
            self.assertTrue(all(count == 1 for count in counts.values()), counts)
            self.assertTrue(progress)
            setup = next(row for row in rows if row.get('entry_type') == 'start_run setup')
            self.assertEqual(setup['plugins.target_type'], 'scripted_demo')
            self.assertEqual(setup['run.scan_profile'], 'full')
            self.assertEqual(setup['run.soft_probe_prompt_cap'], 1)
            dns.assert_not_called()
            connect.assert_not_called()
            http_request.assert_not_called()
            datasets.assert_not_called()


if __name__ == '__main__':
    unittest.main()
