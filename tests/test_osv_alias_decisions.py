"""Raw OSV transport never grants malformed decision identifiers authority."""
from contextlib import ExitStack, contextmanager
import copy
from datetime import date, datetime, timezone
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))
from getzilla import security_data as data  # noqa: E402
from getzilla import known_vulns as legacy  # noqa: E402
from getzilla import security_osv_snapshot as snapshot  # noqa: E402
from getzilla import security_intelligence as intelligence  # noqa: E402
from getzilla import expanded_security as expanded  # noqa: E402
from getzilla import security_cli  # noqa: E402
from getzilla import verification  # noqa: E402
from getzilla import util  # noqa: E402
from tests.osv_owned_ports import snapshot_ports  # noqa: E402

CVE='CVE-2026-12345'
BAD=[' CVE-2026-12345 ', 'CVE-2026-12345,', 'CVE-2026-12345\n', 'cve-2026-12345']
OPAQUE=['GHSA-owned,', ' ', '', 'provider\x1b[31mtext']

@contextmanager
def denied_effects():
    def denied(*args,**kwargs):
        raise AssertionError('unmocked outside fixture effect')
    with ExitStack() as stack:
        for target in ('builtins.open','io.open','os.open','subprocess.Popen','os.system','os.fork',
                       'os.posix_spawn','socket.socket','socket.create_connection','ctypes.CDLL','ctypes.PyDLL'):
            stack.enter_context(patch(target,denied,create=True))
        yield

def record(aliases,*,name='owned',version='1.0.0',identifier='OSV-OWNED-1'):
    return {'id':identifier,'aliases':aliases,'affected':[{
        'package':{'ecosystem':'PyPI','name':name},'versions':[version]}]}

def archive(records):
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w') as zipout:
        for index,value in enumerate(records):
            zipout.writestr(zipfile.ZipInfo(f'owned-{index}.json',date_time=(2026,1,1,0,0,0)),json.dumps(value))
    return output.getvalue()

def offline(module,records):
    payload=archive(records)
    with ExitStack() as stack:
        snapshot_ports(stack,module,payload)
        stack.enter_context(denied_effects())
        data.osv_coverage(payload,'PyPI')
        return module.query_offline([module.Dependency('PyPI','owned','1.0.0','owned.lock')],Path('/owned-db'))

class AliasDecisionTests(unittest.TestCase):
    def test_transport_retains_opaque_strings_and_raw_bytes(self):
        raw=record(OPAQUE+[CVE])
        before=copy.deepcopy(raw)
        payload=archive([raw])
        with denied_effects():
            aliases=data.osv_aliases(raw)
            coverage=data.osv_coverage(payload,'PyPI')
        self.assertEqual(aliases,OPAQUE+[CVE])
        self.assertEqual(raw,before)
        self.assertEqual(coverage['record_count'],1)
        self.assertEqual(payload,archive([raw]))

    def test_matched_consumers_keep_raw_separate_from_safe_projection(self):
        for module in (legacy,snapshot):
            finding,=offline(module,[record(OPAQUE+[CVE,'OSV_PUBLIC:1'])])
            self.assertEqual(finding.raw_aliases,OPAQUE+[CVE,'OSV_PUBLIC:1'])
            self.assertEqual(finding.aliases,[CVE,'OSV_PUBLIC:1'])
            self.assertEqual(finding.to_dict()['raw_aliases'],OPAQUE+[CVE,'OSV_PUBLIC:1'])

    def test_unrelated_or_unaffected_malformed_cve_does_not_poison_transport(self):
        for module in (legacy,snapshot):
            findings=offline(module,[record([BAD[0]],name='other',identifier='OSV-OTHER'),
                record([BAD[1]],version='2.0.0',identifier='OSV-UNMATCHED'),record([CVE])])
            self.assertEqual(len(findings),1)
            self.assertEqual(findings[0].aliases,[CVE])

    def test_matched_malformed_cve_refuses_even_with_a_valid_cve(self):
        for module in (legacy,snapshot):
            for bad in BAD:
                with self.assertRaises(module.VulnerabilityError):
                    offline(module,[record([CVE,bad])])

    def test_malformed_cve_primary_refuses_at_matched_decision(self):
        for module in (legacy,snapshot):
            with self.assertRaises(module.VulnerabilityError):
                offline(module,[record([CVE],identifier=BAD[0])])

    def test_online_malformed_primary_refuses_before_detail_lookup(self):
        for module in (legacy,snapshot):
            for identifier in (BAD[0],BAD[3],None):
                calls=[]
                def fetch(url,body):
                    calls.append(url)
                    if url.endswith('/querybatch'):
                        return json.dumps({'results':[{'vulns':[{'id':identifier}]}]}).encode()
                    raise AssertionError('detail lookup before primary validation')
                with denied_effects(), self.assertRaises(module.VulnerabilityError):
                    module.query_online([module.Dependency('PyPI','owned','1.0.0','owned.lock')],fetch=fetch)
                self.assertEqual(calls,[module.OSV_API+'/querybatch'])

    def test_shape_errors_remain_global_before_unrelated_filter(self):
        for module in (legacy,snapshot):
            for aliases in ('not-an-array',[None],False):
                with self.assertRaises((module.VulnerabilityError,data.SecurityDataError)):
                    offline(module,[record(aliases,name='other')])

    def test_enrichment_rejects_bad_raw_projection_before_any_lookup(self):
        class NoLookup(dict):
            def get(self,*args):
                raise AssertionError('lookup of uncertain identities')
        for bad in BAD:
            for aliases,raw in (([],[bad]),([CVE],[CVE,bad])):
                finding={'id':'OSV-OWNED-1','aliases':aliases,'raw_aliases':raw}
                with denied_effects(), self.assertRaises(intelligence.IntelligenceError):
                    intelligence.enrich_findings([finding],{'records':NoLookup()},
                        {'records':NoLookup(),'score_date':'owned','model_version':'owned'})

    def test_canonical_enrichment_retains_hit_zero_and_unknown(self):
        finding={'id':'OSV-OWNED-1','aliases':[CVE],'raw_aliases':OPAQUE+[CVE,'CVE-2026-54321']}
        with denied_effects():
            result,=intelligence.enrich_findings([finding],{'records':{CVE:{}}},
                {'records':{CVE:{'score':0.0,'percentile':0.0}},'score_date':'owned','model_version':'owned'})
        self.assertTrue(result['intelligence'][CVE]['known_exploited'])
        self.assertEqual(result['intelligence'][CVE]['epss'],0.0)
        self.assertIsNone(result['intelligence']['CVE-2026-54321']['epss'])
        self.assertEqual(result['intelligence']['CVE-2026-54321']['epss_state'],'unknown')

    def scanned(self,module,raw,accepted_id):
        dependency=module.Dependency('PyPI','owned','1.0.0','owned.lock')
        finding=module.Finding(dependency,'OSV-OWNED-1',aliases=[],raw_aliases=raw)
        config={'exclude':[],'accept':[{'id':accepted_id,'expires':'2099-01-01'}]}
        with ExitStack() as stack:
            proof=snapshot_ports(stack,module,archive([record(raw)]))
            def owned_findings(dependencies,database,*,now=None,source_evidence=None):
                self.assertEqual(dependencies,[dependency])
                self.assertEqual(database,Path('/owned-db'))
                source_evidence.append(copy.deepcopy(proof))
                return [finding]
            stack.enter_context(patch.object(module,'load_config',return_value=config))
            stack.enter_context(patch.object(module,'collect_dependencies',return_value=([dependency],[])))
            if module is legacy:
                stack.enter_context(patch.object(module,'dependency_inventory',
                    return_value=([dependency],[],{'fixture':'owned dependency'})))
            stack.enter_context(patch.object(module,'query_offline',side_effect=owned_findings))
            stack.enter_context(denied_effects())
            return module.scan(Path('/owned-project'),environ={'GETZILLA_OSV_DB':'/owned-db'},today=date(2026,11,17))

    def test_both_scan_waivers_rederive_raw_not_caller_projection(self):
        for module in (legacy,snapshot):
            report=self.scanned(module,OPAQUE,OPAQUE[0])
            self.assertEqual(report['status'],'fail')
            self.assertEqual(report['accepted'],[])
            report=self.scanned(module,['OSV_PUBLIC:1'],'OSV_PUBLIC:1')
            self.assertEqual(report['status'],'pass')
            self.assertEqual(len(report['accepted']),1)
            with self.assertRaises(module.VulnerabilityError):
                self.scanned(module,[CVE,BAD[0]],'OSV-OWNED-1')

    def inventory(self):
        return {'complete':True,'digest':'a'*64,'dependencies':[
            {'ecosystem':'PyPI','name':'owned','version':'1.0.0','manifest':'owned.lock'}],
            'images':[],'gaps':[]}

    def test_expanded_waiver_cannot_hide_malformed_raw_identity(self):
        finding=snapshot.Finding(snapshot.Dependency('PyPI','owned','1.0.0','owned.lock'),
            'OSV-OWNED-1',aliases=[CVE],raw_aliases=[CVE,BAD[0]])
        with ExitStack() as stack:
            stack.enter_context(patch.object(Path,'resolve',return_value=Path('/owned-project')))
            stack.enter_context(patch.object(expanded,'_policy_digest',return_value='b'*64))
            stack.enter_context(patch.object(expanded,'query_offline',return_value=[finding]))
            stack.enter_context(patch.object(expanded,'load_config',return_value={
                'accept':[{'id':'OSV-OWNED-1','expires':'2099-01-01'}]}))
            stack.enter_context(denied_effects())
            report=expanded.known_vulnerability_report(Path('/owned-project'),inventory=self.inventory(),
                environ={},now=datetime(2026,11,17,tzinfo=timezone.utc))
            finding.raw_aliases=[CVE,*OPAQUE]
            valid_report=expanded.known_vulnerability_report(Path('/owned-project'),inventory=self.inventory(),
                environ={},now=datetime(2026,11,17,tzinfo=timezone.utc))
        self.assertEqual((report['status'],report['reason_code']),('fail','data-unavailable'))
        self.assertEqual(report['accepted'],[])
        self.assertEqual(valid_report['status'],'pass')
        self.assertEqual(len(valid_report['accepted']),1)

    def expanded_checks(self,finding,*,valid=False):
        obligations=[{'check_id':name,'applicability':'required' if name in {
            'security-kev','security-epss','security-malicious-packages'} else 'not_applicable',
            'data_sources':[]} for name in expanded.CHECK_FAMILIES]
        class NoLookup(dict):
            def __contains__(self,key):
                raise AssertionError('uncertain lookup')
            def get(self,*args):
                raise AssertionError('uncertain lookup')
        def feed(database,source_id,now):
            value={'records':NoLookup()}
            if valid:
                value=({'records':{CVE:{}}} if source_id=='kev' else
                    {'records':{CVE:{'score':0.0,'percentile':0.0}},'score_date':'owned','model_version':'owned'})
            return value,{}
        with ExitStack() as stack:
            stack.enter_context(patch.object(Path,'resolve',return_value=Path('/owned-project')))
            stack.enter_context(patch.object(expanded,'_policy_digest',return_value='b'*64))
            stack.enter_context(patch.object(expanded,'security_obligations',return_value=obligations))
            stack.enter_context(patch.object(expanded,'query_offline',return_value=[finding]))
            stack.enter_context(patch.object(expanded,'_read_source',side_effect=feed))
            stack.enter_context(patch.object(expanded,'_database_name',return_value='owned-db'))
            # Required source identity remains exact; only lookup data is a trap.
            for item in obligations:
                if item['check_id'] in {'security-kev','security-epss'}:
                    item['data_sources']=[{'database':'owned-db'}]
            stack.enter_context(denied_effects())
            return {item['name']:item for item in expanded.run_checks(Path('/owned-project'),
                inventory=self.inventory(),environ={},now=datetime(2026,11,17,tzinfo=timezone.utc))}

    def test_expanded_kev_epss_and_mal_refuse_uncertain_alias_before_absence_credit(self):
        finding=snapshot.Finding(snapshot.Dependency('PyPI','owned','1.0.0','owned.lock'),
            'OSV-OWNED-1',aliases=[CVE],raw_aliases=[CVE,BAD[0]])
        results=self.expanded_checks(finding)
        for name in ('security-kev','security-epss','security-malicious-packages'):
            self.assertEqual(results[name]['details'][0]['outcome'],'blocked')
            self.assertTrue(results[name]['details'][0]['gaps'])

    def test_expanded_canonical_kev_epss_and_mal_still_consume_all_findings(self):
        finding=snapshot.Finding(snapshot.Dependency('PyPI','owned','1.0.0','owned.lock'),
            'MAL-OWNED-1',aliases=[CVE],raw_aliases=[CVE,*OPAQUE],accepted_until='2099-01-01')
        results=self.expanded_checks(finding,valid=True)
        self.assertEqual(results['security-kev']['details'][0]['outcome'],'finding')
        self.assertEqual(results['security-malicious-packages']['details'][0]['outcome'],'finding')
        detail=results['security-epss']['details'][0]
        self.assertEqual(detail['outcome'],'pass')
        self.assertEqual(detail['findings'][0]['intelligence'][CVE]['epss'],0.0)

    def test_closed_report_consumer_rejects_bad_raw_under_safe_projection(self):
        finding=snapshot.Finding(snapshot.Dependency('PyPI','owned','1.0.0','owned.lock'),
            'OSV-OWNED-1',aliases=[CVE],accepted_until='2099-01-01',raw_aliases=[CVE,BAD[0]]).to_dict()
        now=datetime(2026,11,17,tzinfo=timezone.utc)
        with denied_effects():
            accepted=security_cli._findings_consistent('known-vulnerabilities',{'findings':[],'accepted':[finding]},now)
            epss=security_cli._findings_consistent('security-epss',{'findings':[
                {**finding,'intelligence':{},'enrichment_reason':'no-cve-alias'}]},now)
        self.assertFalse(accepted)
        self.assertFalse(epss)

    def test_raw_human_projection_is_bounded_json_without_terminal_controls(self):
        with denied_effects():
            display=data.osv_alias_text(['\x1b[31m'+'z'*10000,'line\nnext'])
        self.assertNotIn('\x1b',display)
        self.assertNotIn('\n',display)
        self.assertEqual(len(json.loads(display)),2)
        self.assertLess(len(display),6000)

    def test_verifier_text_projection_escapes_retained_raw_aliases(self):
        finding=snapshot.Finding(snapshot.Dependency('PyPI','owned','1.0.0','owned.lock'),
            'OSV-OWNED-1',aliases=[CVE],raw_aliases=OPAQUE).to_dict()
        with denied_effects():
            detail=verification._vulnerability_detail(finding)
        self.assertNotIn('\x1b',detail['raw_aliases'])
        self.assertEqual(json.loads(detail['raw_aliases']),OPAQUE[:3])

    def test_cli_human_projection_escapes_control_bearing_raw_alias(self):
        finding=snapshot.Finding(snapshot.Dependency('PyPI','owned','1.0.0','owned.lock'),
            'OSV-OWNED-1',aliases=[CVE],raw_aliases=['opaque\x1b[31m\nvalue']).to_dict()
        report={'status':'fail','summary':'owned unresolved finding','findings':[finding],'accepted':[]}
        script=ROOT/'scripts/getzilla_vulns.py'
        code=compile(script.read_bytes(),str(script),'exec')
        output=io.StringIO()
        def recheck_projection(root,current,*,environ):
            self.assertEqual(root,Path('/owned-project'))
            self.assertIs(current,report)
            self.assertEqual(output.getvalue(),'')
        with ExitStack() as stack:
            stack.enter_context(patch.object(legacy,'scan',return_value=report))
            recheck=stack.enter_context(patch.object(legacy,'recheck_report',side_effect=recheck_projection))
            stack.enter_context(patch.object(util,'find_root',return_value=Path('/owned-project')))
            stack.enter_context(patch.object(sys,'argv',['getzilla_vulns.py']))
            stack.enter_context(patch.object(sys,'stdout',output))
            stack.enter_context(patch.dict('os.environ',{'GITHUB_ACTIONS':'false'},clear=True))
            stack.enter_context(denied_effects())
            with self.assertRaises(SystemExit) as stopped:
                exec(code,{'__file__':str(script),'__name__':'__main__'})
        self.assertEqual(stopped.exception.code,1)
        self.assertEqual(recheck.call_count,1)
        self.assertNotIn('\x1b',output.getvalue())
        self.assertIn('\\u001b',output.getvalue())
        self.assertIn('\\n',output.getvalue())

    def test_cli_json_roundtrips_raw_unicode_without_terminal_format_controls(self):
        finding=snapshot.Finding(snapshot.Dependency('PyPI','owned','1.0.0','owned.lock'),
            'OSV-OWNED-1',aliases=[],raw_aliases=['opaque\u202evalue']).to_dict()
        report={'status':'fail','summary':'owned unresolved finding','findings':[finding],'accepted':[]}
        script=ROOT/'scripts/getzilla_vulns.py'
        code=compile(script.read_bytes(),str(script),'exec')
        output=io.StringIO()
        def recheck_projection(root,current,*,environ):
            self.assertEqual(root,Path('/owned-project'))
            self.assertIs(current,report)
            self.assertEqual(output.getvalue(),'')
        with ExitStack() as stack:
            stack.enter_context(patch.object(legacy,'scan',return_value=report))
            recheck=stack.enter_context(patch.object(legacy,'recheck_report',side_effect=recheck_projection))
            stack.enter_context(patch.object(util,'find_root',return_value=Path('/owned-project')))
            stack.enter_context(patch.object(sys,'argv',['getzilla_vulns.py','--json']))
            stack.enter_context(patch.object(sys,'stdout',output))
            stack.enter_context(denied_effects())
            with self.assertRaises(SystemExit):
                exec(code,{'__file__':str(script),'__name__':'__main__'})
        self.assertEqual(recheck.call_count,1)
        self.assertNotIn('\u202e',output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['findings'][0]['raw_aliases'],finding['raw_aliases'])


if __name__=='__main__':
    unittest.main()
