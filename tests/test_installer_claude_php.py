"""Official manifest/release shapes only; no real native binary or build runs."""
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))
from getzilla import latest_releases as releases, managed_source_build


class ClaudePhpTests(unittest.TestCase):
    def test_claude_current_native_platform_and_exact_manifest_size_hash(self):
        calls=[]
        def fetch(url):
            calls.append(url)
            if url.endswith('/latest'):
                return b'4.0.0\n'
            self.assertEqual(url,'https://downloads.claude.ai/claude-code-releases/4.0.0/manifest.json')
            return json.dumps(dict(version='4.0.0',platforms={'win32-arm64':dict(binary='claude.exe',checksum='a'*64,size=10)})).encode()
        target=releases.claude_release(fetch,'windows','arm64')
        self.assertEqual(target.url,'https://downloads.claude.ai/claude-code-releases/4.0.0/win32-arm64/claude.exe')
        self.assertEqual(target.requirements['size'],10)
        with self.assertRaises(ValueError):
            releases.claude_release(fetch,'windows','x64')
        self.assertEqual(sum(u.endswith('/latest') for u in calls),2)

    def test_php_source_uses_global_latest_official_sha_not_old_compatible(self):
        catalog={'8':dict(version='8.9.9',source=[]),'9':dict(version='9.0.0',source=[dict(filename='php-9.0.0.tar.gz',sha256='b'*64)])}
        target=releases.php_source(lambda _:json.dumps(catalog).encode())
        self.assertEqual(target.version,'9.0.0')
        self.assertEqual(target.url,'https://www.php.net/distributions/php-9.0.0.tar.gz')
        catalog['9']['source'][0]['sha256']='missing'
        with self.assertRaises(ValueError):
            releases.php_source(lambda _:json.dumps(catalog).encode())

    def test_linux_php_build_reuses_exact_local_custody_and_preserves_tamper(self):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:gz') as archive:
            member=tarfile.TarInfo('php-owned/configure')
            member.mode=0o755
            member.size=5
            archive.addfile(member,io.BytesIO(b'inert'))
        data=stream.getvalue()
        target=releases.Target('php','9.0.0','https://www.php.net/distributions/php-9.0.0.tar.gz',
                              sha256=hashlib.sha256(data).hexdigest(),filename='php-9.0.0.tar.gz')
        parent=ROOT/'.getzilla/runtime/scratch'
        parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-php-build-',dir=parent) as owned:
            root=Path(owned)
            calls=[]
            prefix=None
            def run(command,cwd=None,**kwargs):
                nonlocal prefix
                calls.append(command)
                if command[0]=='./configure':
                    prefix=Path(next(a.split('=',1)[1] for a in command if a.startswith('--prefix=')))
                if command[:2]==['make','install']:
                    (prefix/'bin').mkdir(parents=True)
                    (prefix/'bin/php').write_bytes(b'inert compiled PHP')
                return subprocess.CompletedProcess(command,0,'PHP 9.0.0 (cli)\n','')
            binary=managed_source_build.install_source(target,data,root,run=run)
            before=len(calls)
            self.assertEqual(managed_source_build.install_source(target,data,root,run=run),binary)
            self.assertEqual(len(calls)-before,1)
            self.assertEqual(calls[-1],[str(binary),'--version'])
            from unittest.mock import patch
            from getzilla import managed_software
            phar=b'inert Composer PHAR'
            composer=releases.Target('composer','3.0.0','https://getcomposer.org/download/3.0.0/composer.phar',
                sha256=hashlib.sha256(phar).hexdigest(),filename='composer.phar',requirements={'php':90000})
            def public_run(command,cwd=None,**kwargs):
                if any(str(a).endswith('composer.phar') for a in command):
                    return subprocess.CompletedProcess(command,0,'Composer version 3.0.0\n','')
                return run(command,cwd,**kwargs)
            with patch.object(managed_software,'plan',return_value=({'php':target,'composer':composer},[])), \
                 patch.object(managed_software,'verify_environment',return_value=dict(component='python-environment',status='complete')), \
                 patch.dict(os.environ):
                report=managed_software.install_software(root,root,tools=('composer',),fetch=lambda url:phar if url==composer.url else data,
                                                        run=public_run,system='linux',architecture='x64')
            self.assertEqual(report['status'],'complete',report)
            self.assertTrue((root/'bin/composer').is_file())
            binary.write_bytes(b'user edit')
            with self.assertRaisesRegex(ValueError,'conflict'):
                managed_source_build.install_source(target,data,root,run=run)
            self.assertEqual(binary.read_bytes(),b'user edit')

    def test_claude_public_join_uses_verified_direct_binary_without_vendor_install(self):
        from unittest.mock import patch
        from getzilla import managed_software, managed_runtime
        data=b'inert native Claude'
        target=releases.Target('claude','4.0.0','https://downloads.claude.ai/claude-code-releases/4.0.0/linux-x64/claude',
                              sha256=hashlib.sha256(data).hexdigest(),filename='claude',requirements={'size':len(data)})
        parent=ROOT/'.getzilla/runtime/scratch'
        parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-claude-native-',dir=parent) as owned:
            calls=[]
            def run(command,cwd=None,**kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command,0,'4.0.0 (Claude Code)\n','')
            with patch.object(managed_software,'plan',return_value=({'agent:claude':target},[])), \
                 patch.object(managed_software,'verify_environment',return_value=dict(component='python-environment',status='complete')):
                result=managed_software.install_software(Path(owned)/'state',Path(owned),agent='claude',fetch=lambda _:data,run=run)
            self.assertEqual(result['status'],'complete',result)
            self.assertEqual(len(calls),1)
            self.assertEqual(calls[0][-1],'--version')
            wrong=releases.Target('claude','4.0.0',target.url,sha256=target.sha256,filename='claude',requirements={'size':len(data)+1})
            with self.assertRaisesRegex(ValueError,'size'):
                managed_runtime.entries(wrong,data)
