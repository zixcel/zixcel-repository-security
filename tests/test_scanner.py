import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from zixcel_repository_security.scanner import scan_repository, _documents

class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'repo'
        self.root.mkdir()
        self.engine = self.base / 'engine'
        self.engine.write_text("#!/usr/bin/python3\nimport pathlib,sys\npathlib.Path(next(a.split('=',1)[1] for a in sys.argv if a.startswith('--report-path='))).write_text('[]')\n")
        self.engine.chmod(0o700)
        self.config = {'repository_id': 'test-repo', 'gitleaks': {'path': str(self.engine), 'sha256': hashlib.sha256(self.engine.read_bytes()).hexdigest()}}
    def scan(self, **kwargs):
        return scan_repository(self.root, self.config, **kwargs)
    def test_detection_receipt_does_not_contain_detected_values(self):
        private = 'Private ' + 'Subject'
        self.root.joinpath('source.txt').write_text(private + '\n' + 'user@' + 'private-customer.invalid-domain.com')
        result = self.scan(terms=[{'id':'person-01','category':'person','values':[private]}])
        self.assertEqual(result['status'], 'findings')
        self.assertNotIn(private, json.dumps(result))
        self.assertNotIn('user@', json.dumps(result))
        self.assertEqual({f['rule'] for f in result['findings']}, {'registered-private-person', 'email-address'})
    def test_registration_is_excluded_but_tracked_registration_is_blocked(self):
        subprocess.run(['git','init','-q',str(self.root)],check=True)
        self.root.joinpath('.gitignore').write_text('/registration/\n')
        self.root.joinpath('registration').mkdir()
        self.root.joinpath('registration/account.json').write_text('{}')
        self.assertEqual(self.scan()['status'],'passed')
        subprocess.run(['git','-C',str(self.root),'add','-f','registration/account.json'],check=True)
        result=self.scan()
        self.assertIn('tracked-excluded-data',{f['rule'] for f in result['findings']})
        exception={'fingerprint':result['findings'][0]['fingerprint'],'expires':'2099-01-01','reason':'cannot waive excluded tracked data','reviewer':'local-review'}
        self.assertEqual(self.scan(exceptions=[exception])['status'],'findings')
    def test_symlinks_and_binary_formats_are_incomplete(self):
        self.root.joinpath('link').symlink_to(self.engine)
        self.root.joinpath('binary').write_bytes(bytes([255,0,255]))
        self.assertEqual(self.scan()['status'],'incomplete')
    def test_tar_traversal_is_rejected_without_extracting(self):
        with tarfile.open(self.root/'bad.tgz','w:gz') as archive:
            item=tarfile.TarInfo('../escaped');item.size=4
            archive.addfile(item,io.BytesIO(b'data'))
        self.assertEqual(self.scan()['status'],'incomplete')
        self.assertFalse((self.base/'escaped').exists())
    def test_nested_archives_share_one_expansion_budget(self):
        def archive(name, payload):
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w:gz') as tar:
                member=tarfile.TarInfo(name);member.size=len(payload)
                tar.addfile(member,io.BytesIO(payload))
            return stream.getvalue()
        nested=archive('payload.txt',b'a'*700)
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:gz') as tar:
            for name in ['one.tgz','two.tgz']:
                member=tarfile.TarInfo(name);member.size=len(nested)
                tar.addfile(member,io.BytesIO(nested))
        with patch('zixcel_repository_security.scanner.MAX_TOTAL',1000):
            self.assertTrue(any(text is None for _,text in _documents('root.tgz',stream.getvalue())))
    def test_missing_engine_and_changed_engine_do_not_pass(self):
        self.assertEqual(scan_repository(self.root,{'repository_id':'test'})['status'],'incomplete')
        self.engine.write_text('changed')
        with self.assertRaises(ValueError): self.scan()
    def test_exception_expires_and_is_invalidated_by_file_change(self):
        self.root.joinpath('source.txt').write_text('Private Subject')
        terms=[{'id':'person-01','category':'person','values':['Private Subject']}]
        receipt=self.scan(terms=terms)
        exception={'fingerprint':receipt['findings'][0]['fingerprint'],'expires':'2099-01-01','reason':'intentional synthetic fixture','reviewer':'local-review'}
        self.assertEqual(self.scan(terms=terms,exceptions=[exception])['status'],'passed')
        self.root.joinpath('source.txt').write_text('Private Subject changed')
        self.assertEqual(self.scan(terms=terms,exceptions=[exception])['status'],'findings')
        exception['expires']='2000-01-01'
        self.assertEqual(self.scan(terms=terms,exceptions=[exception])['status'],'findings')

if __name__ == '__main__': unittest.main()
