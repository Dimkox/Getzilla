"""Offline contract checks. Never contact a collector."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla.install_analytics import Store, collect, client_event, vendor_jobs

class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'events.sqlite')
        self.addCleanup(self.store.close)
        self.now = 1800000000
        self.token = self.store.issue(consent=True, now=self.now, identifiers={'ga_client_id':'123.456', 'ga_session_id':'123', 'metrika_client_id':'123456'}, source={'utm_source':'test'}, session_start=self.now, session_end=self.now+100)
        self.event = {'token':self.token, 'event_id':'a'*32, 'event':'getzilla_install_complete', 'version':'2.3.1', 'os':'Linux', 'occurred_at':self.now+20}
    def test_invalid_expired_declined_malformed(self):
        for edit in ({'token':'bad'},{'unexpected':'secret'},{'occurred_at':True},{'os':'path/private'}):
            with self.assertRaises(ValueError):
                collect(self.store, self.event|edit, now=self.now+21)
        with self.assertRaises(ValueError):
            collect(self.store,self.event,now=self.now+90000)
        with self.assertRaises(ValueError):
            self.store.issue(consent=False,now=self.now,identifiers={},source={})
    def test_duplicate_upgrade_keeps_actual_time_and_source(self):
        self.assertTrue(collect(self.store,self.event,now=self.now+21))
        self.assertFalse(collect(self.store,self.event|{'version':'3.0'},now=self.now+22))
        record=self.store.event('a'*32)
        self.assertEqual(record['occurred_at'],self.now+20)
        self.assertEqual(record['source'],{'utm_source':'test'})
        self.assertEqual(record['delivery']['ga4']['processing'],'unknown')
        self.assertEqual(record['delivery']['metrika']['attribution'],'unknown')
    def test_missing_identifiers_and_out_of_window(self):
        self.assertEqual(vendor_jobs(self.event,{},now=self.now+21),{})
        ids={'ga_client_id':'123.456','ga_session_id':'123','metrika_client_id':'123456','session_start':self.now,'session_end':self.now+100}
        jobs=vendor_jobs(self.event,ids,now=self.now+21)
        self.assertEqual(jobs['ga4']['body']['timestamp_micros'],(self.now+20)*1000000)
        self.assertEqual(jobs['metrika']['row']['DateTime'],self.now+20)
        self.assertNotIn('ga4',vendor_jobs(self.event,ids,now=self.now+73*3600))
        self.assertNotIn('metrika',vendor_jobs(self.event,ids,now=self.now+20+21*86400))
        jobs=vendor_jobs(self.event,ids,now=self.now+25*3600)
        self.assertNotIn('session_id',jobs['ga4']['body']['events'][0]['params'])
    def test_client_consent_ci_readiness_offline_and_stable_identity(self):
        env={'GETZILLA_INSTALL_ANALYTICS':'1','GETZILLA_INSTALL_TOKEN':self.token,'GETZILLA_INSTALL_ANALYTICS_ENDPOINT':'https://getzilla.app/api/install-complete'}
        sent=[]
        for changes in ({'GETZILLA_INSTALL_ANALYTICS':'0'},{'CI':'true'},{'GETZILLA_INTERNAL_RUN':'1'},{'GETZILLA_INSTALL_TOKEN':''},{'GETZILLA_INSTALL_ANALYTICS_ENDPOINT':'https://evil.test'}):
            self.assertFalse(client_event(Path(self.tmp.name), '2.3.1', env|changes, ready=True, send=lambda p: sent.append(p),now=self.now))
        self.assertFalse(client_event(Path(self.tmp.name),'2.3.1',env,ready=False,send=lambda p:sent.append(p),now=self.now))
        self.assertFalse(sent)
        def offline(payload):
            sent.append(payload)
            raise OSError('offline')
        self.assertFalse(client_event(Path(self.tmp.name),'2.3.1',env,ready=True,send=offline,now=self.now))
        self.assertTrue(client_event(Path(self.tmp.name),'3.0',env,ready=True,send=lambda p:sent.append(p),now=self.now+10))
        self.assertEqual(sent[0]['event_id'],sent[1]['event_id'])
        self.assertEqual(sent[0]['occurred_at'],sent[1]['occurred_at'])
        self.assertEqual(set(sent[0]),set(self.event))

if __name__=='__main__':
    unittest.main()

class InstallerIntegrationTests(unittest.TestCase):
    def test_bash_completion_rejects_failed_doctor(self):
        import subprocess
        root=Path(__file__).resolve().parents[1]
        source=(root/'scripts/install.sh').read_text().rsplit('main "$@"',1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            fake=Path(tmp)/'.venv/bin/python'
            fake.parent.mkdir(parents=True)
            fake.write_text('#!/bin/bash\ncase "$*" in\n *getzilla_doctor.py*) exit "${DOCTOR_RESULT:-0}";;\n *getzilla_install_analytics.py*) echo event >> "$GETZILLA_HOME/events";;\nesac\nexit 0\n')
            fake.chmod(0o700)
            overrides='''
ensure_git_and_python() { :; }
find_python() { echo "$GETZILLA_HOME/.venv/bin/python"; }
choose_agent() { echo qwen; }
choose_provider() { echo native; }
choose_eu_ai_act() { :; }
fetch_getzilla() { :; }
link_getzilla_command() { :; }
setup_python_env() { :; }
install_agent() { :; }
configure_agent() { return "${AGENT_RESULT:-0}"; }
update_security_data() { :; }
install_workflow_baseline() { :; }
agent_command() { echo qwen; }
main
'''
            import os
            env=os.environ|{'GETZILLA_HOME':tmp,'GETZILLA_NONINTERACTIVE':'1','DOCTOR_RESULT':'1'}
            run=subprocess.run(['bash','-c',source+overrides],env=env,capture_output=True)
            self.assertEqual(run.returncode,3,run.stderr)
            self.assertFalse((Path(tmp)/'events').exists())
            env['DOCTOR_RESULT']='0'
            env['AGENT_RESULT']='1'
            self.assertEqual(subprocess.run(['bash','-c',source+overrides],env=env,capture_output=True).returncode,3)
            self.assertFalse((Path(tmp)/'events').exists())
            env['AGENT_RESULT']='0'
            run=subprocess.run(['bash','-c',source+overrides],env=env,capture_output=True)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual((Path(tmp)/'events').read_text(),'event\n')
    def test_powershell_call_is_after_success_branch_and_bounded_helper(self):
        root=Path(__file__).resolve().parents[1]
        source=(root/'scripts/install.ps1').read_text()
        start=source.index('if ($DoctorExit -eq 0 -and $AgentExit -eq 0)')
        call=source.index("Join-Path $GetzillaHome 'scripts/getzilla_install_analytics.py'")
        fail=source.index('throw "Getzilla installation is incomplete',start)
        self.assertLess(start,fail)
        self.assertLess(fail,call)
        self.assertIn('catch { }',source[call:call+120])

class PowerShellRuntimeTests(unittest.TestCase):
    def test_powershell_final_readiness(self):
        import shutil
        import subprocess
        if not shutil.which('pwsh'):
            self.skipTest('PowerShell host unavailable')
        root=Path(__file__).resolve().parents[1]
        source=(root/'scripts/install.ps1').read_text()
        segment=source[source.index("    $PythonText = $Python -join ' '"):source.index("    Write-Host 'Next:'")]
        with tempfile.TemporaryDirectory() as tmp:
            script=Path(tmp)/'probe.ps1'
            prelude='''
$ErrorActionPreference='Stop'
$Python=@('python')
$GetzillaHome=$env:PROBE_HOME
$Agent='qwen'
$AgentExit=[int]$env:AGENT_RESULT
function Write-Step { }
function Invoke-Python($python,$arguments) {
 $global:LASTEXITCODE=0
 if ($arguments[0] -like '*getzilla_install_managed.py') { $global:LASTEXITCODE=[int]$env:MANAGED_RESULT }
 if ($arguments[0] -like '*getzilla_doctor.py') { $global:LASTEXITCODE=[int]$env:DOCTOR_RESULT }
 if ($arguments[0] -like '*getzilla_install_analytics.py') { Add-Content -LiteralPath (Join-Path $GetzillaHome 'events') -Value 'event' }
}
'''
            script.write_text(prelude+segment)
            import os
            env=os.environ|{'PROBE_HOME':tmp,'AGENT_RESULT':'0','DOCTOR_RESULT':'0','MANAGED_RESULT':'0'}
            for field in ('AGENT_RESULT','DOCTOR_RESULT','MANAGED_RESULT'):
                run=subprocess.run(['pwsh','-NoProfile','-File',str(script)],env=env|{field:'1'},capture_output=True)
                self.assertNotEqual(run.returncode,0,run.stdout)
                self.assertFalse((Path(tmp)/'events').exists())
            run=subprocess.run(['pwsh','-NoProfile','-File',str(script)],env=env,capture_output=True)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual((Path(tmp)/'events').read_text().strip(),'event')

class BoundaryTests(AnalyticsTests):
    def test_revocation_and_consent_scope(self):
        self.store.revoke(self.token)
        with self.assertRaises(ValueError):
            collect(self.store,self.event,now=self.now+21)
        token=self.store.issue(consent=True,now=self.now,identifiers={},source={})
        self.store.db.execute('UPDATE tokens SET record=?',(json.dumps({'consent':False,'scope':'other'}),))
        self.store.db.commit()
        with self.assertRaises(ValueError):
            collect(self.store,self.event|{'token':token},now=self.now+21)
    def test_transport_parent_deadline_and_no_ready(self):
        import importlib.util
        from unittest.mock import patch
        import subprocess
        path=Path(__file__).resolve().parents[1]/'scripts/getzilla_install_analytics.py'
        spec=importlib.util.spec_from_file_location('install_analytics_cli',path)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(sys,'argv',[str(path)]),patch.object(module.subprocess,'run') as run:
            module.main()
            run.assert_not_called()
        with patch.object(sys,'argv',[str(path),'--ready']),patch.object(module.subprocess,'run',side_effect=subprocess.TimeoutExpired('test',4)) as run:
            module.main()
            self.assertEqual(run.call_args.kwargs['timeout'],4)
    def test_delivery_is_not_processing_and_has_upload_id(self):
        collect(self.store,self.event,now=self.now+21)
        self.store.delivery('a'*32,'metrika',accepted=True,processing='pending',upload_id='1234')
        state=self.store.event('a'*32)['delivery']['metrika']
        self.assertEqual(state,{'accepted':True,'processing':'pending','attribution':'unknown','upload_id':'1234'})
