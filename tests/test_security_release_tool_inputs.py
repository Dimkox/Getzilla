"""Inert Nuitka release data never enters Python import or binary execution."""
import hashlib
import struct
import sys
import unittest
import zlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))
from getzilla import security_release_tool_inputs as release
from getzilla.security_artifacts import ArtifactError


def member(name,body,flags=0):
    return name.encode()+b'\0'+bytes([flags])+struct.pack('<QI',len(body),zlib.crc32(body))+body


class NuitkaTests(unittest.TestCase):
    def test_inventory_hashes_actual_member_bytes_and_retains_terms(self):
        raw=member('app.bin',b'\x7fELF',1)+member('pkg/LICENSE',b'actual terms')+b'\0'
        inventory,terms=release.nuitka_members(raw)
        self.assertEqual(inventory['app.bin'],{'size':4,'sha256':hashlib.sha256(b'\x7fELF').hexdigest()})
        self.assertEqual(terms,{'pkg/LICENSE':b'actual terms'})

    def test_corrupt_crc_truncated_size_links_and_duplicate_names_fail(self):
        good=member('app.bin',b'data')
        badcrc=bytearray(good);badcrc[-1]^=1
        for raw in [bytes(badcrc)+b'\0',good[:-1]+b'\0',member('../bad',b'x')+b'\0',
                    member('app.bin',b'x',2)+b'\0',good+good+b'\0',good+b'\0junk']:
            with self.subTest(raw=raw[:20]),self.assertRaises(ArtifactError):release.nuitka_members(raw)

    def test_elf_parser_rejects_wrong_architecture_and_unbounded_section_table(self):
        for raw in [b'PKfake',b'\x7fELF'+bytes(60)]:
            with self.assertRaises(ArtifactError):release.elf_sections(raw)

    def test_unresolved_native_components_never_become_root_license_record(self):
        result=release.component_frontier({'opengrep.bin':{'sha256':'a'*64,'size':4}}, {},
            {'license':b'LGPL terms','workflow':b'nuitka[onefile]==4.1.3','opam':b'license: "LGPL-2.1-only"'})
        self.assertFalse(result['complete'])
        self.assertIn('release-component-sbom-missing',[g['code'] for g in result['gaps']])
        self.assertEqual(result['components'],[])

if __name__=='__main__':unittest.main()

class SourceProofTests(unittest.TestCase):
    def test_missing_raw_asset_produces_named_gap_without_network_for_other_tools(self):
        import tempfile
        from datetime import datetime,timezone
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            result=release.prepare({'tools':[{'kind':'release-tool','reference':'https://github.com/other/tool/releases/download/v1/x'}]},root/'artifacts',root/'tools',now=datetime(2026,11,18,tzinfo=timezone.utc))
            self.assertEqual(result,{'records':[],'gaps':[],'bound_bytes':0,'frontiers':[]})

    def test_source_identity_refuses_unpinned_commit_before_native_decode(self):
        record={'subject':{'kind':'release-tool','reference':release.URL,'artifact_sha256':release.SHA256,'platform':'linux/amd64'},
                'sha256':release.SHA256,'filename':'opengrep_manylinux_x86','origin':{'kind':'github-release-native-v1','source_commit':'0'*40}}
        with self.assertRaises(ArtifactError) as error:release.read_source(Path('/missing'),record,b'wrong')
        self.assertEqual(error.exception.code,'artifact-origin')

class DispatchTests(unittest.TestCase):
    def test_native_origin_never_accepts_unproved_root_component_partition(self):
        from getzilla import security_artifacts
        record={'origin':{'kind':'github-release-native-v1'}}
        from unittest.mock import patch
        with patch.object(release,'read_source',return_value=({}, {}, [], {}, {})):
            with self.assertRaises(ArtifactError) as error:
                security_artifacts._release_source(Path('/not-read'),record,b'raw')
        self.assertEqual(error.exception.code,'release-component-sbom-missing')

    def test_member_namespace_cannot_assign_file_as_directory(self):
        raw=member('pkg',b'x')+member('pkg/LICENSE',b'terms')+b'\0'
        with self.assertRaises(ArtifactError):release.nuitka_members(raw)

# A small, real zstd frame of the inert Nuitka member stream above.
FRAME='KLUv/QRYrQEAxAJhcHAuYmluAAEEADoS8wxFTEZ4cGtnL0xJQ0VOU0UAAAUAcT+iiHRlcm1zAAIAwWgD8AJs544X'

def elf_fixture():
    import base64
    data=b'KAY'+base64.b64decode(FRAME)
    names=b'\0.rodata\0.shstrtab\0';offset=64+len(data)+len(names)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),2,62,1,0,0,offset,0,64,0,0,64,3,2)
    sections=bytes(64)+struct.pack('<IIQQQQIIQQ',1,1,0,0,64,len(data),0,0,1,0)+struct.pack('<IIQQQQIIQQ',9,3,0,0,64+len(data),len(names),0,0,1,0)
    return header+data+names+sections


class RawContainerTests(unittest.TestCase):
    @unittest.skipUnless(Path('/usr/bin/zstd').is_file(),'qualified fixed system zstd decoder unavailable')
    def test_actual_elf_nuitka_decoder_checks_container_and_crc(self):
        from unittest.mock import patch
        raw=elf_fixture()
        with patch.multiple(release,SIZE=len(raw),SHA256=hashlib.sha256(raw).hexdigest()):
            members,terms,container=release.raw_inventory(raw)
        self.assertEqual(set(members),{'app.bin','pkg/LICENSE'})
        self.assertEqual(terms,{'pkg/LICENSE':b'terms'})
        self.assertEqual(container['members'],2)
        self.assertEqual(container['expanded_bytes'],56)

    def test_truncated_zstd_and_reserved_blocks_fail(self):
        for raw in [b'\x28\xb5\x2f\xfd\x08\x00',b'\x28\xb5\x2f\xfd\x00\x88\x07\x00\x00']:
            with self.assertRaises(ArtifactError):release._frame_end(raw,0)

class CatalogFrontierTests(unittest.TestCase):
    def test_acquisition_rejects_caller_asserted_frontier_budget_and_gaps(self):
        import tempfile
        from getzilla.security_license_acquisition import acquire_pypi
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ArtifactError):
                acquire_pypi([],Path(directory),inventory_digest='a'*64,
                    family_preparation={'records':[],'gaps':[],'bound_bytes':0,'frontiers':[{'path':'absent','sha256':'a'*64}]})


def source_fixture():
    import base64,json
    from getzilla.security_artifacts import _git_tree
    raw=elf_fixture();digest=hashlib.sha256(raw).hexdigest();sources={};rows={};blobs={}
    for alias,(name,_) in release.SOURCES.items():
        body=('inert '+alias).encode();sha=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()
        sources[alias]=(name,sha);rows[name]={'path':name,'mode':'100644','type':'blob','sha':sha,'size':len(body)}
        blobs[release.API+'/git/blobs/'+sha]={'sha':sha,'size':len(body),'encoding':'base64','content':base64.b64encode(body).decode()}
    tree=_git_tree(rows);commit='1'*40
    data={release.URL:raw,release.API+'/releases/tags/v1.30.1':{'tag_name':'v1.30.1','target_commitish':commit,
        'assets':[{'name':'opengrep_manylinux_x86','browser_download_url':release.URL,'size':len(raw),'digest':'sha256:'+digest}]},
        release.API+'/git/commits/'+commit:{'sha':commit,'tree':{'sha':tree}},
        release.API+'/git/trees/'+tree+'?recursive=1':{'sha':tree,'truncated':False,'tree':list(rows.values())},**blobs}
    data={url:body if isinstance(body,bytes) else json.dumps(body).encode() for url,body in data.items()}
    return {'SIZE':len(raw),'SHA256':digest,'COMMIT':commit,'TREE':tree,'SOURCES':sources},data


@unittest.skipUnless(Path('/usr/bin/zstd').is_file(),'qualified fixed system zstd decoder unavailable')
class ActualPublicationTests(unittest.TestCase):
    def test_source_producer_retains_distinct_uses_and_publishes_rederived_gaps(self):
        import tempfile,copy
        from unittest.mock import patch
        from datetime import datetime,timezone
        from getzilla.security_license_acquisition import acquire_pypi
        pins,data=source_fixture();calls=[];now=datetime(2026,11,18,tzinfo=timezone.utc)
        subject={'kind':'release-tool','reference':release.URL,'artifact_sha256':pins['SHA256'],'platform':'linux/amd64',
                 'manifest':'.github/workflows/check.yml','line':10,'source_sha256':'a'*64,'usage':'build-ci'}
        other={**subject,'line':30}
        def fetch(url,maximum):
            calls.append(url);return data[url],{'requested_url':url,'final_url':url,'status':200}
        with tempfile.TemporaryDirectory() as directory,patch.multiple(release,**pins):
            root=Path(directory);artifacts=root/'artifacts'
            prepared=release.prepare({'tools':[subject,subject,other]},artifacts,root/'tools',now=now,fetch=fetch)
            self.assertEqual(len(prepared['frontiers']),2)
            self.assertEqual(len(calls),8)
            prepared['gaps']=[];prepared['bound_bytes']=0
            bundle=acquire_pypi([],artifacts,inventory_digest='b'*64,now=now,family_preparation=prepared)
            self.assertEqual(bundle['records'],[])
            self.assertEqual(len(bundle['family_frontiers']),2)
            self.assertEqual(len(bundle['gaps']),6)
            self.assertEqual({g['subject']['line'] for g in bundle['gaps']},{10,30})
            with self.assertRaises(ArtifactError) as error:
                acquire_pypi([],artifacts,inventory_digest='b'*64,now=now,family_preparation=prepared,byte_budget=1)
            self.assertEqual(error.exception.code,'artifact-size')

    def test_saved_source_commit_asset_and_license_corruption_are_rejected(self):
        import tempfile,json
        from unittest.mock import patch
        from datetime import datetime,timezone
        pins,data=source_fixture();now=datetime(2026,11,18,tzinfo=timezone.utc)
        subject={'kind':'release-tool','reference':release.URL,'artifact_sha256':pins['SHA256'],'platform':'linux/amd64',
                 'manifest':'check.yml','line':1,'source_sha256':'a'*64,'usage':'build-ci'}
        cases=[('release',release.API+'/releases/tags/v1.30.1','target_commitish','0'*40),
               ('commit',release.API+'/git/commits/'+pins['COMMIT'],'sha','0'*40),
               ('license',release.API+'/git/blobs/'+pins['SOURCES']['license'][1],'content','AAAA')]
        for label,url,key,value in cases:
            changed=dict(data);obj=json.loads(changed[url]);obj[key]=value;changed[url]=json.dumps(obj).encode()
            with self.subTest(label=label),tempfile.TemporaryDirectory() as directory,patch.multiple(release,**pins):
                with self.assertRaises(ArtifactError) as error:
                    release.prepare({'tools':[subject]},Path(directory)/'artifacts',Path(directory)/'tools',now=now,
                        fetch=lambda url,maximum:(changed[url],{'requested_url':url,'final_url':url,'status':200}))
                self.assertEqual(error.exception.code,'artifact-origin')

    def test_stale_frontier_and_changed_raw_are_not_reused(self):
        import tempfile
        from unittest.mock import patch
        from datetime import datetime,timezone,timedelta
        pins,data=source_fixture();now=datetime(2026,11,18,tzinfo=timezone.utc)
        subject={'kind':'release-tool','reference':release.URL,'artifact_sha256':pins['SHA256'],'platform':'linux/amd64',
                 'manifest':'check.yml','line':1,'source_sha256':'a'*64,'usage':'build-ci'}
        with tempfile.TemporaryDirectory() as directory,patch.multiple(release,**pins):
            root=Path(directory);artifacts=root/'artifacts'
            prepared=release.prepare({'tools':[subject]},artifacts,root/'tools',now=now,
                fetch=lambda url,maximum:(data[url],{'requested_url':url,'final_url':url,'status':200}))
            with self.assertRaises(ArtifactError) as error:release.validate_preparation(artifacts,prepared['frontiers'],now=now+timedelta(hours=73))
            self.assertEqual(error.exception.code,'artifact-stale')
            (artifacts/'objects'/pins['SHA256']).write_bytes(b'corrupt')
            with self.assertRaises(ArtifactError) as error:release.validate_preparation(artifacts,prepared['frontiers'],now=now)
            self.assertEqual(error.exception.code,'artifact-hash')

class BuildLogTests(unittest.TestCase):
    def test_build_installs_remain_candidates_and_nuitka_exclusions_are_recorded(self):
        import io,zipfile
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as archive:
            archive.writestr(release.BINARY_LOG,'2026-09-21T21:47:09Z Successfully installed opengrep-1.30.1 attrs-26.1.0\n2026-09-21T21:47:16Z Nuitka-Options: --noinclude-setuptools-mode=nofollow\n')
            archive.writestr(release.CORE_LOG,'2026-09-21T21:20:23Z -> installed \x1b[01mhttp\x1b[0m.6.0.0\n2026-09-21T21:19:31Z Cache restored from key: Linux-X64-v2-opam-5.5.0-deadbeef\n')
        observed=release.build_observations(output.getvalue())
        self.assertFalse(observed['runtime_component_closure_complete'])
        self.assertEqual(observed['python_build_installs'][0]['name'],'attrs')
        self.assertEqual(observed['ocaml_build_installs'][0]['version'],'6.0.0')
        self.assertEqual(observed['nuitka_exclusions'],['setuptools'])

@unittest.skipUnless(Path('/usr/bin/zstd').is_file(),'qualified fixed system zstd decoder unavailable')
class FrontierClaimTests(unittest.TestCase):
    def test_complete_flag_or_missing_source_terms_cannot_publish_a_complete_catalog(self):
        import tempfile,json,copy
        from unittest.mock import patch
        from datetime import datetime,timezone
        from getzilla.security_license_acquisition import acquire_pypi
        pins,data=source_fixture();now=datetime(2026,11,18,tzinfo=timezone.utc)
        subject={'kind':'release-tool','reference':release.URL,'artifact_sha256':pins['SHA256'],'platform':'linux/amd64',
                 'manifest':'check.yml','line':1,'source_sha256':'a'*64,'usage':'build-ci'}
        with tempfile.TemporaryDirectory() as directory,patch.multiple(release,**pins):
            root=Path(directory);artifacts=root/'artifacts'
            prepared=release.prepare({'tools':[subject]},artifacts,root/'tools',now=now,
                fetch=lambda url,maximum:(data[url],{'requested_url':url,'final_url':url,'status':200}))
            acquire_pypi([],artifacts,inventory_digest='b'*64,now=now,family_preparation=prepared)
            before=(artifacts/'manifest.json').read_bytes()
            descriptor=prepared['frontiers'][0];front=json.loads((artifacts/descriptor['path']).read_bytes());front['complete']=True
            body=json.dumps(front).encode();digest=hashlib.sha256(body).hexdigest();path='proofs/'+digest;(artifacts/path).write_bytes(body)
            tampered={**descriptor,'path':path,'sha256':digest};bad={**prepared,'frontiers':[tampered]}
            with self.assertRaises(ArtifactError) as error:acquire_pypi([],artifacts,inventory_digest='b'*64,now=now,family_preparation=bad)
            self.assertEqual(error.exception.code,'license-transitive-coverage')
            self.assertEqual((artifacts/'manifest.json').read_bytes(),before)
            front['complete']=False;license_path=front['record']['origin']['source_files']['license']['path'];(artifacts/license_path).unlink()
            with self.assertRaises(ArtifactError):acquire_pypi([],artifacts,inventory_digest='b'*64,now=now,family_preparation=prepared)
            self.assertEqual((artifacts/'manifest.json').read_bytes(),before)

@unittest.skipUnless(Path('/usr/bin/zstd').is_file(),'qualified fixed system zstd decoder unavailable')
class SharedBudgetTests(unittest.TestCase):
    def test_factory_catalog_counts_unqualified_source_data_and_rechecks_age(self):
        import tempfile
        from unittest.mock import patch
        from datetime import datetime,timezone,timedelta
        from getzilla.security_license_acquisition import acquire_pypi
        from getzilla.security_factory_inputs import _catalog_bytes
        pins,data=source_fixture();now=datetime(2026,11,18,tzinfo=timezone.utc)
        subject={'kind':'release-tool','reference':release.URL,'artifact_sha256':pins['SHA256'],'platform':'linux/amd64',
                 'manifest':'check.yml','line':1,'source_sha256':'a'*64,'usage':'build-ci'}
        with tempfile.TemporaryDirectory() as directory,patch.multiple(release,**pins):
            root=Path(directory);artifacts=root/'artifacts'
            prepared=release.prepare({'tools':[subject]},artifacts,root/'tools',now=now,
                fetch=lambda url,maximum:(data[url],{'requested_url':url,'final_url':url,'status':200}))
            typed={'schema_version':1,'providers':[{'kind':'opengrep-release-v1','frontiers':prepared['frontiers']}]}
            acquire_pypi([],artifacts,inventory_digest='b'*64,now=now,family_preparation=typed)
            expected=prepared['bound_bytes']+len((artifacts/'manifest.json').read_bytes())
            self.assertEqual(_catalog_bytes(artifacts,now=now),expected)
            with self.assertRaises(ArtifactError) as error:_catalog_bytes(artifacts,now=now+timedelta(hours=73))
            self.assertEqual(error.exception.code,'artifact-stale')

    def test_unknown_provider_cannot_join_the_catalog(self):
        import tempfile
        from getzilla.security_license_acquisition import acquire_pypi
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ArtifactError):
                acquire_pypi([],Path(directory),inventory_digest='a'*64,
                    family_preparation={'schema_version':1,'providers':[{'kind':'caller-approved','report':{}}]})
            self.assertFalse((Path(directory)/'manifest.json').exists())
