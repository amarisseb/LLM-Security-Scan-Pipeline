"""Offline production config checks; all writes use temporary directories."""
import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml
from tools import serve_production as production

ROOT = Path(__file__).resolve().parents[1]


class ProductionConfigTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data = Path(tmp.name).resolve() / 'private'
        env = patch.dict(os.environ, {
            'ARISEC_SELF_SERVE': '1', 'ARISEC_LOCAL_DEMO': '0', 'ARISEC_LOCAL_PREVIEW': '0',
            'ARISEC_PUBLIC_ORIGIN': 'https://scan.example.com', 'DATA_DIR': str(self.data),
        }, clear=True)
        env.start()
        self.addCleanup(env.stop)
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)

    def test_validate_is_read_only_and_fail_closed_flags(self):
        config = production.validate_config()
        self.assertEqual(config.public_origin, 'https://scan.example.com')
        self.assertEqual(config.forwarded_allow_ips, '172.30.23.2')
        self.assertFalse(self.data.exists())
        for key, value in [('ARISEC_SELF_SERVE', '0'), ('ARISEC_LOCAL_DEMO', '1'), ('ARISEC_LOCAL_PREVIEW', '1')]:
            with patch.dict(os.environ, {key: value}):
                with self.assertRaises(ValueError):
                    production.validate_config()
        self.assertFalse(self.data.exists())

    def test_reject_invalid_origin_proxy_and_paths(self):
        cases = {
            'ARISEC_PUBLIC_ORIGIN': ['http://scan.example.com', 'https://127.0.0.1', 'https://metadata.google.internal',
                                    'https://user@scan.example.com', 'https://scan.example.com/path',
                                    'https://scan.example.com/', 'https://scan.example.com?x=1', ''],
            'FORWARDED_ALLOW_IPS': ['*', '172.30.23.0/29', '127.0.0.1', '172.30.23.2,172.30.23.3'],
            'DATA_DIR': ['', 'relative', str(Path(self.data.anchor)), str(self.data / '..' / 'escape')],
            'ARISEC_EXAMPLE_ENDPOINT': ['http://127.0.0.1:8000/demo/endpoint'],
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                    with self.assertRaises(ValueError):
                        production.validate_config()
        self.assertFalse(self.data.exists())

    def test_private_paths_fixed_inside_data_and_foreign_overrides_ignored(self):
        with patch.dict(os.environ, ARISEC_ACCOUNTS_DB='outside.sqlite3', SCAN_OUTPUT_DIR='outside',
                        ATTESTATION_LOG_PATH='outside.jsonl', ARISEC_ACCOUNTS_FILE='legacy.json', CORS_ALLOW_ORIGIN_REGEX='.*'):
            production.configure_environment(production.validate_config())
            for key in ['ARISEC_ACCOUNTS_DB', 'SCAN_OUTPUT_DIR', 'ATTESTATION_LOG_PATH', 'HOME', 'XDG_CACHE_HOME', 'HF_HOME', 'TORCH_HOME']:
                self.assertTrue(Path(os.environ[key]).is_relative_to(self.data))
            self.assertEqual(Path(os.environ['ARISEC_ACCOUNTS_DB']), self.data / 'accounts.sqlite3')
            self.assertNotIn('ARISEC_ACCOUNTS_FILE', os.environ)
            self.assertNotIn('CORS_ALLOW_ORIGIN_REGEX', os.environ)
            self.assertEqual(os.environ['ENABLE_DOCS'], '0')

    def test_main_single_worker_only_exact_proxy_no_service_started(self):
        with patch('uvicorn.run') as run:
            production.main()
        run.assert_called_once_with('app.pilot:app', host='0.0.0.0', port=8000, workers=1,
                                    proxy_headers=True, forwarded_allow_ips='172.30.23.2',
                                    server_header=False, access_log=False)

    def test_import_starts_no_server_or_storage(self):
        with patch('uvicorn.run') as run:
            importlib.reload(production)
        run.assert_not_called()
        self.assertFalse(self.data.exists())

    def test_compose_boundary_and_proxy_addresses(self):
        config = yaml.safe_load((ROOT / 'deploy' / 'compose.yaml').read_text(encoding='utf-8-sig'))
        app, caddy = config['services']['app'], config['services']['caddy']
        self.assertNotIn('ports', app)
        self.assertTrue(app['read_only'])
        self.assertTrue(app['init'])
        self.assertEqual(app['user'], '10001:10001')
        self.assertEqual(app['cap_drop'], ['ALL'])
        self.assertEqual(app['environment']['FORWARDED_ALLOW_IPS'], '172.30.23.2')
        self.assertEqual(caddy['networks']['edge']['ipv4_address'], '172.30.23.2')
        self.assertEqual(app['networks']['edge']['ipv4_address'], '172.30.23.3')
        self.assertEqual(config['networks']['edge']['ipam']['config'][0]['subnet'], '172.30.23.0/29')
        self.assertEqual(caddy['ports'], ['80:80', '443:443'])
        self.assertEqual(caddy['image'], 'caddy:2-alpine')
        self.assertIn('arisec_data:/data', app['volumes'])
        self.assertTrue(app['mem_limit'])
        self.assertTrue(app['pids_limit'])
        self.assertIn('/health', str(app['healthcheck']['test']))

    def test_image_cpu_index_nonroot_and_allowlisted_context(self):
        dockerfile = (ROOT / 'deploy' / 'Dockerfile').read_text(encoding='utf-8-sig')
        self.assertIn('FROM python:3.12-slim-bookworm', dockerfile)
        self.assertIn('https://download.pytorch.org/whl/cpu', dockerfile)
        self.assertLess(dockerfile.index('install --index-url'), dockerfile.index('install -c'))
        self.assertIn('USER 10001:10001', dockerfile)
        self.assertNotIn('COPY . ', dockerfile)
        self.assertIn('tools/manage_consultations.py', dockerfile)
        ignore = (ROOT / '.dockerignore').read_text(encoding='utf-8-sig')
        self.assertIn('\n**\n', ignore)
        self.assertNotIn('!.venv', ignore)
        self.assertNotIn('!.git', ignore)
        self.assertNotIn('!.arisec-private', ignore)


if __name__ == '__main__':
    unittest.main()
