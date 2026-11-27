import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import main, lab_policy, scan_store


class PreviewWorkerTargetTests(unittest.TestCase):
    def test_only_exact_admitted_destination_reaches_worker(self):
        target='http://127.0.0.1:3001/api/v1/workspace/test/chat'
        other='http://127.0.0.1:9000/unrelated'
        previous=lab_policy.configured_local_targets()
        self.addCleanup(lab_policy.configure_local_targets,previous)
        lab_policy.configure_local_targets([target,other])
        for enabled,url,expected in [('1',target,[target]),('0',target,None),('1',target+'/other',None)]:
            with self.subTest(enabled=enabled,url=url), tempfile.TemporaryDirectory() as tmp:
                store=scan_store.ScanStore(tmp)
                sid='a'*32
                store.create(sid,url,mode='http')
                captured=[]
                def worker(kind,scan_id,payload,*args,**kwargs):
                    captured.append(dict(payload))
                    return Path(tmp)/'garak.test.report.jsonl'
                with patch.dict(os.environ,{'ARISEC_LOCAL_PREVIEW':enabled,'ARISEC_LOCAL_DEMO':'0'}), patch.object(main,'store',store), patch.object(main,'run_isolated_job',side_effect=worker), patch.object(main.results,'answered_any',return_value=True):
                    main._run_isolated_scan('http',sid,{'url':url})
                self.assertEqual(captured[0].get('lab_targets'),expected)
                self.assertNotIn('scripted_demo',captured[0])
