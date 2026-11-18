"""Finite OpenGrep release adapter. Read Nuitka data; never execute the asset.

A source license and a build dependency list do not establish a binary SBOM.
Keep those facts and the unresolved component frontier separate.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import selectors
import struct
import subprocess
import tempfile
import time
import urllib.request
import zlib
from pathlib import Path

from .security_artifacts import (ArtifactError, MAX_ARCHIVE_BYTES, MAX_ARTIFACT_BYTES,
    MAX_INDEX_BYTES, MAX_MEMBERS, MAX_METADATA_BYTES, artifact_context, read_file,
    safe_parts, _saved_proof, _git_tree)
from .security_data import _clock

URL='https://github.com/opengrep/opengrep/releases/download/v1.30.1/opengrep_manylinux_x86'
SHA256='d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4'
SIZE=46553256
COMMIT='525e67142af506e2f3ea1728d18c5824813f0248'
TREE='6cbeada93cb5095700d569bd00b7e980488b261e'
API='https://api.github.com/repos/opengrep/opengrep'
SOURCES={
 'license':('LICENSE','8000a6faacf471c537530805ab29523c7732e11a'),
 'workflow':('.github/workflows/build-manylinux-binary.yml','72e61f4929ec934054e9c63657ed4d0b888161ab'),
 'dune':('dune-project','c3bc0ce605ffa46fc21e99d1d4a2a6248d06f875'),
 'opam':('opam/semgrep.opam','78b4f2356be40783c892857f58c05dedd053c8d2')}


def fail(code,message):
    raise ArtifactError(code,message)


def elf_sections(raw):
    """Read supported little-endian ELF64 data ranges, including Nuitka rodata."""
    if len(raw)<64 or raw[:7]!=b'\x7fELF\x02\x01\x01':fail('release-format','expected ELF64 little-endian version 1')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    offset,size,count,names=h[6],h[11],h[12],h[13]
    if h[1]!=2 or h[2]!=62 or size!=64 or not 0<count<=MAX_MEMBERS or names>=count or offset+size*count>len(raw):
        fail('release-format','ELF platform or section table is unsupported')
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,offset+i*size) for i in range(count)]
    table=sections[names]
    if table[1]!=3 or table[5]>MAX_METADATA_BYTES or table[4]+table[5]>len(raw):fail('release-format','ELF section names are unbounded')
    strings=raw[table[4]:table[4]+table[5]];result={}
    for row in sections[1:]:
        end=strings.find(b'\0',row[0])
        if row[0]>=len(strings) or end<0:fail('release-format','ELF section name is invalid')
        try:name=strings[row[0]:end].decode('ascii')
        except UnicodeError:fail('release-format','ELF section name is not ASCII')
        if name in result or row[1]!=8 and row[4]+row[5]>len(raw):fail('release-format','ELF sections are ambiguous or truncated')
        result[name]={'offset':row[4],'size':row[5],'type':row[1]}
    return result


def _frame_end(raw,start):
    """Bound one standard Zstandard frame without interpreting compressed data."""
    if raw[start:start+4]!=b'\x28\xb5\x2f\xfd' or start+6>len(raw):fail('release-format','Nuitka compressed payload lacks its Zstandard frame')
    flag=raw[start+4]
    if flag&0x18:fail('release-format','unsupported Zstandard frame flags')
    index=start+5+(not bool(flag&32))+[0,1,2,4][flag&3]
    index+=1 if flag&32 and flag>>6==0 else [0,2,4,8][flag>>6]
    for _ in range(MAX_MEMBERS):
        if index+3>len(raw):fail('release-format','truncated Zstandard block header')
        block=int.from_bytes(raw[index:index+3],'little');index+=3
        kind=(block>>1)&3;size=block>>3
        if kind==3 or size>128*1024:fail('release-format','unsupported Zstandard block')
        index+=1 if kind==1 else size
        if index>len(raw):fail('release-format','truncated Zstandard block')
        if block&1:
            index+=4 if flag&4 else 0
            if index>len(raw):fail('release-format','truncated Zstandard checksum')
            return index
    fail('artifact-size','Zstandard block count exceeds the archive member bound')


def _decode(frame):
    """Use the fixed system data decoder with bounded memory, output and time."""
    with tempfile.TemporaryFile() as source:
        source.write(frame);source.seek(0)
        process=subprocess.Popen(['/usr/bin/zstd','-d','-c','--memory=128MB'],stdin=source,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LANG':'C'},close_fds=True)
        total=0;chunks=[];started=time.monotonic()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic()-started>60:fail('release-decode-timeout','Nuitka data decoding exceeded 60 seconds')
                    for key,_ in selector.select(0.2):
                        block=os.read(key.fd,65536)
                        if not block:selector.unregister(key.fileobj);continue
                        total+=len(block)
                        if total>MAX_ARCHIVE_BYTES:fail('artifact-size','Nuitka expanded data exceeds the archive byte bound')
                        chunks.append(block)
            if process.wait(timeout=1)!=0:fail('release-format','Nuitka Zstandard data decoding failed')
            return b''.join(chunks)
        finally:
            if process.poll() is None:process.kill()
            process.wait();process.stdout.close()


def nuitka_members(raw):
    if len(raw)>MAX_ARCHIVE_BYTES:fail('artifact-size','Nuitka members exceed the expanded archive bound')
    index=0;members={};terms={}
    while index<len(raw):
        end=raw.find(b'\0',index,min(len(raw),index+1025))
        if end<0:fail('release-format','Nuitka filename is unbounded or truncated')
        if end==index:
            if end!=len(raw)-1 or not members:fail('release-format','Nuitka end marker is ambiguous')
            from .security_artifacts import _check_git_namespace
            _check_git_namespace(members)
            return members,terms
        try:name=raw[index:end].decode('utf-8')
        except UnicodeError:fail('release-format','Nuitka filename is not UTF-8')
        safe_parts(name);index=end+1
        if index+13>len(raw) or name in members or len(members)>=MAX_MEMBERS:fail('release-format','Nuitka member header is truncated or repeated')
        flags=raw[index];size,crc=struct.unpack_from('<QI',raw,index+1);index+=13
        if flags not in {0,1} or index+size>len(raw):fail('release-format','Nuitka member flags/size are unsupported')
        body=raw[index:index+size];index+=size
        if zlib.crc32(body)!=crc:fail('artifact-hash','Nuitka member CRC differs')
        members[name]={'sha256':hashlib.sha256(body).hexdigest(),'size':size}
        if any(part.upper().startswith(('LICENSE','COPYING','NOTICE')) for part in name.split('/')):
            if size>MAX_METADATA_BYTES:fail('artifact-size','Nuitka legal text exceeds the metadata bound')
            terms[name]=body
    fail('release-format','Nuitka payload lacks its end marker')


def raw_inventory(payload):
    if len(payload)!=SIZE or hashlib.sha256(payload).hexdigest()!=SHA256:fail('artifact-hash','OpenGrep raw asset differs from its reviewed pin')
    sections=elf_sections(payload);section=sections.get('.rodata')
    if section is None:fail('release-format','Nuitka ELF lacks rodata')
    data=payload[section['offset']:section['offset']+section['size']]
    signature=b'KAY\x28\xb5\x2f\xfd';start=data.find(signature)
    if start<0 or data.find(signature,start+1)>=0:fail('release-format','Nuitka onefile signature is missing or ambiguous')
    frame=start+3;end=_frame_end(data,frame)
    expanded=_decode(data[frame:end]);members,terms=nuitka_members(expanded)
    return members,terms,{'format':'nuitka-onefile-linux-kay-zstd-crc32','expanded_bytes':len(expanded),
        'frame_offset':section['offset']+frame,'frame_bytes':end-frame,'members':len(members)}


def component_frontier(members,terms,source):
    missing=[name for name in members if name not in terms]
    return {'complete':False,'components':[], 'member_inventory':members,
        'retained_term_paths':sorted(terms),'source_paths':sorted(source),
        'gaps':[{'code':'release-component-sbom-missing','message':'Nuitka member hashes identify files, not the compiled Python/OCaml/C component closure',
                 'members_requiring_component_mapping':missing},
                {'code':'release-component-terms-missing','message':'Source LGPL terms do not establish terms for bundled third-party components'},
                {'code':'release-component-policy-missing','message':'Exact component expressions and use-specific license decisions require the verified component closure'}]}


def read_source(root,record,payload):
    """Validate the exact release, full Git tree, selected blobs and raw container.

    The fixed tree metadata has 12,076 entries. It is bounded by the existing
    metadata byte limit. No source archive is acquired or expanded.
    """
    subject=record['subject'];origin=record['origin']
    expected={'kind','index_url','index_path','index_sha256','artifact_url','source_commit',
        'commit_path','commit_sha256','tree_path','tree_sha256','source_files'}
    if (set(origin)!=expected or origin['kind']!='github-release-native-v1' or origin['source_commit']!=COMMIT
            or origin['index_url']!=API+'/releases/tags/v1.30.1' or origin['artifact_url']!=URL
            or subject.get('kind')!='release-tool' or subject.get('reference')!=URL
            or subject.get('platform')!='linux/amd64' or subject.get('artifact_sha256')!=SHA256
            or record.get('sha256')!=SHA256 or record.get('filename')!='opengrep_manylinux_x86'):
        fail('artifact-origin','raw OpenGrep source/asset identity differs from the reviewed pin')
    evidence=[]
    def proof(path,digest):
        raw,value=_saved_proof(root,path,digest)
        evidence.append({'path':path,'sha256':digest,'bytes':len(raw)})
        return value
    release=proof(origin['index_path'],origin['index_sha256'])
    if release.get('tag_name')!='v1.30.1' or release.get('target_commitish')!=COMMIT or not isinstance(release.get('assets'),list):
        fail('artifact-origin','raw release source commit is unresolved or differs')
    assets=[a for a in release['assets'] if isinstance(a,dict) and a.get('name')=='opengrep_manylinux_x86']
    if (len(assets)!=1 or assets[0].get('browser_download_url')!=URL or assets[0].get('digest')!='sha256:'+SHA256
            or assets[0].get('size')!=SIZE):fail('artifact-origin','raw release asset URL, size or digest differs')
    commit=proof(origin['commit_path'],origin['commit_sha256']);tree=proof(origin['tree_path'],origin['tree_sha256'])
    if (commit.get('sha')!=COMMIT or commit.get('tree',{}).get('sha')!=TREE or tree.get('sha')!=TREE
            or tree.get('truncated') is not False or not isinstance(tree.get('tree'),list)):
        fail('artifact-origin','raw tool needs its exact commit and complete Git tree')
    rows={};seen=set()
    for row in tree['tree']:
        if not isinstance(row,dict):fail('artifact-origin','source tree row is malformed')
        path=row.get('path');safe_parts(path)
        if path in seen:fail('artifact-origin','source tree repeats a path')
        seen.add(path)
        if row.get('type')=='tree' and row.get('mode')=='040000':continue
        if (row.get('mode'),row.get('type')) not in {('100644','blob'),('100755','blob'),('120000','blob'),('160000','commit')}:
            fail('artifact-origin','source tree has an unsupported Git entry')
        if not isinstance(row.get('sha'),str) or len(row['sha'])!=40:fail('artifact-origin','source tree hash is malformed')
        rows[path]=row
    try:actual_tree=_git_tree(rows)
    except (ValueError,KeyError):fail('artifact-origin','source Git tree cannot be recomputed')
    if actual_tree!=TREE:fail('artifact-origin','source Git tree identity differs')
    descriptors=origin['source_files']
    if not isinstance(descriptors,dict) or set(descriptors)!=set(SOURCES):fail('artifact-origin','raw tool source files are missing or ambiguous')
    source={};files={}
    for alias,(path,git_sha) in SOURCES.items():
        descriptor=descriptors[alias]
        if not isinstance(descriptor,dict) or set(descriptor)!={'path','sha256'}:fail('artifact-origin','source blob descriptor is malformed')
        blob=proof(descriptor['path'],descriptor['sha256']);row=rows.get(path)
        if (row is None or row['mode']!='100644' or row['sha']!=git_sha or blob.get('sha')!=git_sha
                or blob.get('encoding')!='base64' or type(blob.get('size')) is not int
                or not 0<blob['size']<=MAX_METADATA_BYTES or not isinstance(blob.get('content'),str)):
            fail('artifact-origin','source blob does not belong to the retained commit')
        try:body=base64.b64decode(blob['content'].replace('\n',''),validate=True)
        except ValueError:fail('artifact-origin','source Git blob encoding differs')
        digest=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body,usedforsecurity=False).hexdigest()
        if len(body)!=blob['size'] or row.get('size')!=len(body) or digest!=git_sha:fail('artifact-origin','source blob bytes differ from Git')
        source[alias]=body;files['source/'+path]=body
    members,terms,container=raw_inventory(payload)
    files.update(terms)
    return members,files,evidence,container,component_frontier(members,terms,source)


def _fetcher():
    """One finite public-data transaction; no credentials, config, proxy or retry."""
    from .security_acquisition import _HTTPSRedirects
    allowed={URL,API+'/releases/tags/v1.30.1',API+'/git/commits/'+COMMIT,
        API+'/git/trees/'+TREE+'?recursive=1',*(API+'/git/blobs/'+sha for _,sha in SOURCES.values())}
    started=time.monotonic();total=0;requests=0
    def fetch(url,maximum):
        nonlocal total,requests
        if url not in allowed or requests>=8 or time.monotonic()-started>180:fail('artifact-origin','raw release acquisition exceeded its fixed request/deadline scope')
        requests+=1
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),_HTTPSRedirects(url))
        request=urllib.request.Request(url,headers={'User-Agent':'Getzilla-release-evidence/1','Accept-Encoding':'identity'})
        with opener.open(request,timeout=10) as response:
            if response.status!=200 or response.headers.get('Content-Encoding','identity')!='identity':fail('artifact-origin','raw release response is not exact public data')
            declared=response.headers.get('Content-Length')
            if declared is not None and (not declared.isdecimal() or int(declared)>maximum):fail('artifact-size','raw release response exceeds the byte limit')
            chunks=[];size=0
            while chunk:=response.read1(65536):
                size+=len(chunk);total+=len(chunk)
                if size>maximum or total>96*1024*1024 or time.monotonic()-started>180:fail('artifact-size','raw release acquisition exceeded its shared bounds')
                chunks.append(chunk)
            if not size or declared is not None and size!=int(declared):fail('artifact-size','raw release body is empty or incomplete')
            return b''.join(chunks),{'requested_url':url,'final_url':response.geturl(),'status':response.status}
    return fetch


def prepare(inventory,artifacts,tools,*,now=None,fetch=None,build_provenance=None):
    """Acquire finite raw/source data once; retain every exact source-owned use.

    Incomplete native closures are published as inert frontier objects, never as
    qualified license catalog records. The caller publishes the returned gaps
    with the shared package acquisition result.
    """
    subjects=[s for s in inventory.get('tools',[]) if s.get('kind')=='release-tool' and s.get('reference')==URL]
    result={'records':[],'gaps':[],'bound_bytes':0,'frontiers':[]}
    if not subjects:return result
    from .security_license_acquisition import MAX_BATCH_BYTES,MAX_PACKAGES
    unique={json.dumps(subject,sort_keys=True,separators=(',',':')) for subject in subjects}
    if len(subjects)>MAX_PACKAGES or len(unique)*SIZE>MAX_BATCH_BYTES:
        fail('artifact-size','raw release source uses exceed the shared catalog bound')
    from .manifest import _open_root
    from .security_license_acquisition import _write
    artifacts=Path(artifacts);tools=Path(tools);artifacts.mkdir(parents=True,exist_ok=True,mode=0o700)
    root,fd=_open_root(artifacts)
    if not isinstance(fd,int):fail('artifact-platform','raw release producer requires a qualified POSIX directory reader')
    current=_clock(now);fetch=_fetcher() if fetch is None else fetch
    used=0;http=[]
    def save(body,namespace='proofs'):
        nonlocal used
        digest=hashlib.sha256(body).hexdigest();path=namespace+'/'+digest
        _write(fd,path,body,immutable=True);used+=len(body)
        return {'path':path,'sha256':digest}
    def get(url,maximum):
        body,observation=fetch(url,maximum)
        if not isinstance(body,bytes) or not body or len(body)>maximum:fail('artifact-size','raw release fetch returned unbounded data')
        http.append(observation)
        return body
    try:
        build_observed = None
        if build_provenance is not None:
            build_observed, _ = read_build_provenance(root, build_provenance)
        try:payload=read_file(tools,'archives/'+SHA256,MAX_ARTIFACT_BYTES)
        except ArtifactError as exc:
            if (tools/'archives'/SHA256).exists():raise
            payload=get(URL,SIZE)
        if len(payload)!=SIZE or hashlib.sha256(payload).hexdigest()!=SHA256:fail('artifact-hash','raw release cache/download differs from the reviewed pin')
        raw=save(payload,'objects')
        release=save(get(API+'/releases/tags/v1.30.1',MAX_INDEX_BYTES))
        commit=save(get(API+'/git/commits/'+COMMIT,MAX_INDEX_BYTES))
        tree=save(get(API+'/git/trees/'+TREE+'?recursive=1',MAX_INDEX_BYTES))
        blobs={alias:save(get(API+'/git/blobs/'+sha,MAX_METADATA_BYTES)) for alias,(_,sha) in SOURCES.items()}
        origin={'kind':'github-release-native-v1','index_url':API+'/releases/tags/v1.30.1',
            'index_path':release['path'],'index_sha256':release['sha256'],'artifact_url':URL,'source_commit':COMMIT,
            'commit_path':commit['path'],'commit_sha256':commit['sha256'],'tree_path':tree['path'],'tree_sha256':tree['sha256'],'source_files':blobs}
        # Read back every published object through the qualified file reader.
        payload=read_file(root,raw['path'],MAX_ARTIFACT_BYTES)
        seen=set()
        for subject in subjects:
            encoded=json.dumps(subject,sort_keys=True,separators=(',',':'))
            if encoded in seen:continue
            seen.add(encoded)
            record={'schema_version':1,'kind':'tool','subject':subject,'filename':'opengrep_manylinux_x86',
                'path':raw['path'],'sha256':SHA256,'bytes':SIZE,'context':artifact_context(subject),
                'acquired_at':current.isoformat(),'origin':origin}
            members,files,evidence,container,frontier=read_source(root,record,payload)
            front={'schema_version':1,'kind':'release-tool-component-frontier','record':record,'container':container,
                'acquired_at':current.isoformat(),'http':http,'build_provenance':build_provenance,
                'build_observations':build_observed,**frontier}
            saved=save(json.dumps(front,sort_keys=True,separators=(',',':')).encode())
            result['frontiers'].append({**saved,'subject':subject,'acquired_at':current.isoformat()})
            result['gaps'].extend({**gap,'subject':subject,'frontier':saved} for gap in frontier['gaps'])
        verified=validate_preparation(root,result['frontiers'],now=current)
        result['bound_bytes']=verified['bound_bytes']
        result['gaps']=verified['gaps']
        return result
    finally:os.close(fd)


def validate_preparation(root,descriptors,*,now=None,byte_budget=None):
    """Rederive incomplete frontier facts and shared catalog cost from saved data."""
    from .security_data import MAX_AGE_SECONDS,_timestamp
    from .security_license_acquisition import MAX_BATCH_BYTES,MAX_PACKAGES
    byte_budget=MAX_BATCH_BYTES if byte_budget is None else byte_budget
    if type(byte_budget) is not int or not 1<=byte_budget<=MAX_BATCH_BYTES:fail('artifact-size','release frontier budget is invalid')
    if not isinstance(descriptors,list) or len(descriptors)>MAX_PACKAGES:fail('artifact-manifest','release frontiers are malformed or unbounded')
    result={'gaps':[],'frontiers':[],'bound_bytes':0};seen={};current=_clock(now)
    for descriptor in descriptors:
        if not isinstance(descriptor,dict) or set(descriptor)!={'path','sha256','subject','acquired_at'}:fail('artifact-manifest','release frontier descriptor is malformed')
        raw,front=_saved_proof(root,descriptor['path'],descriptor['sha256'])
        if (set(front)!={'schema_version','kind','record','container','acquired_at','http','complete','components','member_inventory','retained_term_paths','source_paths','gaps','build_provenance','build_observations'}
                or type(front['schema_version']) is not int or front['schema_version']!=1 or front['kind']!='release-tool-component-frontier'):
            fail('artifact-manifest','unsupported release frontier schema')
        record=front['record']
        if (not isinstance(record,dict) or set(record)!={'schema_version','kind','subject','filename','path','sha256','bytes','context','acquired_at','origin'}
                or record['kind']!='tool' or record['schema_version']!=1 or record['bytes']!=SIZE
                or record['subject']!=descriptor['subject'] or record['context']!=artifact_context(record['subject'])
                or record['acquired_at']!=descriptor['acquired_at'] or front['acquired_at']!=record['acquired_at']):
            fail('artifact-context','release frontier source/use differs from its descriptor')
        subject=record['subject'];safe_parts(subject.get('manifest'))
        if (type(subject.get('line')) is not int or not 1<=subject['line']<=1000000
                or not isinstance(subject.get('source_sha256'),str) or len(subject['source_sha256'])!=64):
            fail('artifact-context','release frontier needs a source-owned declaration')
        age=(current-_timestamp(record['acquired_at'])).total_seconds()
        if not 0<=age<=MAX_AGE_SECONDS:fail('artifact-stale','release frontier acquisition is future or older than 72 hours')
        key=json.dumps(subject,sort_keys=True,separators=(',',':'))
        if key in seen:
            if seen[key]!=descriptor:fail('artifact-manifest','release frontier repeats a source use with conflicting evidence')
            continue
        seen[key]=descriptor
        if result['bound_bytes']+SIZE>byte_budget:fail('artifact-size','release source frontier exceeds the shared catalog byte budget')
        payload=read_file(root,record['path'],MAX_ARTIFACT_BYTES)
        members,files,evidence,container,expected=read_source(root,record,payload)
        if container!=front['container'] or any(front[k]!=v for k,v in expected.items()):fail('license-transitive-coverage','release frontier claims differ from actual source/container data')
        build_evidence=[]
        observed=None
        if front['build_provenance'] is not None:
            observed,build_evidence=read_build_provenance(root,front['build_provenance'])
        if observed!=front['build_observations']:fail('artifact-origin','frontier build observations differ from retained public data')
        result['bound_bytes']+=len(payload)+len(raw)+sum(row['bytes'] for row in evidence)
        result['bound_bytes']+=sum(row['bytes'] for row in build_evidence)
        if result['bound_bytes']>byte_budget:fail('artifact-size','release source frontier exceeds the shared catalog byte budget')
        result['frontiers'].append(descriptor)
        saved={'path':descriptor['path'],'sha256':descriptor['sha256']}
        result['gaps'].extend({**gap,'subject':subject,'frontier':saved} for gap in expected['gaps'])
    return result


BUILD_RUN_ID=35656341714
BUILD_LOG_SHA256='bf9284b0663be64ff5b0a6b7a3e31328e5caaa759443befd4061b77f9af442fe'
BUILD_CERT_SHA256='1b4e0886e628a92e244524e93312a3037112d524b95685971f766383957b49ec'
BINARY_LOG='8_build-manylinux-binary-x86 _ build-self-contained-manylinux-binary.txt'
CORE_LOG='35_build-linux-x86 _ build-core (5.5.0).txt'


def build_observations(payload):
    """Keep observed build installs distinct from established runtime components."""
    import io
    import re
    import zipfile
    from .security_artifacts import archive_inventory
    inventory=archive_inventory(payload,'logs.zip')
    if BINARY_LOG not in inventory or CORE_LOG not in inventory:fail('artifact-origin','exact OpenGrep build logs are missing')
    python={};ocaml={};exclusions=set();caches=[]
    ansi=re.compile(r'\x1b\[[0-9;]*m')
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for name in (BINARY_LOG,CORE_LOG):
            with archive.open(name) as stream:
                line_number=0
                while raw:=stream.readline(MAX_METADATA_BYTES+1):
                    line_number+=1
                    if len(raw)>MAX_METADATA_BYTES:fail('artifact-size','build log line exceeds the metadata byte bound')
                    line=ansi.sub('',raw.decode('utf-8','strict')).strip()
                    if name==BINARY_LOG and 'Successfully installed ' in line:
                        for token in line.split('Successfully installed ',1)[1].split():
                            match=re.fullmatch(r'([A-Za-z0-9_.-]+)-([0-9][A-Za-z0-9_.+!-]*)',token)
                            if match:
                                package,version=match.groups()
                                python[(package,version)]={'name':package,'version':version,'log':name,'line':line_number,'scope':'build-install-observation'}
                    match=re.search(r'-> installed ([A-Za-z0-9_+-]+)\.([0-9][A-Za-z0-9_.+~-]*)$',line)
                    if name==CORE_LOG and match:
                        package,version=match.groups()
                        ocaml[(package,version)]={'name':package,'version':version,'log':name,'line':line_number,'scope':'build-install-observation'}
                    exclusions.update(re.findall(r'--noinclude-([A-Za-z0-9_-]+)-mode=nofollow',line))
                    if name==CORE_LOG and 'Cache restored from key:' in line:
                        caches.append({'value':line.split('Cache restored from key:',1)[1].strip(),'log':name,'line':line_number})
    return {'runtime_component_closure_complete':False,
        'python_build_installs':[python[key] for key in sorted(python)],
        'ocaml_build_installs':[ocaml[key] for key in sorted(ocaml)],
        'nuitka_exclusions':sorted(exclusions),'restored_build_caches':caches,
        'remaining_inputs':['map compiled Python modules and native libraries to runtime components',
                            'enumerate cached OCaml dependencies and vendored C libraries',
                            'retain exact component license and notice texts; select use-specific policy']}


def read_build_provenance(root,descriptor):
    """Read the retained exact public run logs; never invoke authenticated tools."""
    raw,manifest=_saved_proof(root,descriptor['path'],descriptor['sha256'])
    if (not isinstance(manifest,dict) or set(manifest)!={'schema_version','kind','source_commit','run','logs','certificate'}
            or manifest['schema_version']!=1 or manifest['kind']!='opengrep-public-build-provenance'
            or manifest['source_commit']!=COMMIT):fail('artifact-origin','build provenance belongs to another source')
    evidence=[{'path':descriptor['path'],'sha256':descriptor['sha256'],'bytes':len(raw)}]
    def read(item,maximum):
        if not isinstance(item,dict) or set(item)!={'path','sha256'}:fail('artifact-origin','build provenance descriptor is malformed')
        body=read_file(root,item['path'],maximum)
        if hashlib.sha256(body).hexdigest()!=item['sha256']:fail('artifact-hash','build provenance bytes changed')
        evidence.append({'path':item['path'],'sha256':item['sha256'],'bytes':len(body)})
        return body
    run=json.loads(read(manifest['run'],MAX_INDEX_BYTES))
    runs=run.get('workflow_runs')
    if not isinstance(runs,list):fail('artifact-origin','public run metadata is unavailable')
    selected=[r for r in runs if isinstance(r,dict) and r.get('id')==BUILD_RUN_ID]
    if (len(selected)!=1 or selected[0].get('head_sha')!=COMMIT or selected[0].get('run_attempt')!=1
            or selected[0].get('path')!='.github/workflows/rolling-release.yml'
            or selected[0].get('status')!='completed' or selected[0].get('conclusion')!='success'):
        fail('artifact-origin','public build run differs from the pinned source/release')
    cert=read(manifest['certificate'],MAX_METADATA_BYTES)
    if hashlib.sha256(cert).hexdigest()!=BUILD_CERT_SHA256:fail('artifact-origin','release certificate differs from the retained public asset')
    logs=read(manifest['logs'],MAX_INDEX_BYTES)
    if hashlib.sha256(logs).hexdigest()!=BUILD_LOG_SHA256:fail('artifact-origin','exact public build log artifact differs')
    return {'run_id':BUILD_RUN_ID,'run_attempt':1,'source_commit':COMMIT,
        'assurance':'retained-public-build-data-not-runtime-sbom','observations':build_observations(logs)},evidence


def retain_build_provenance(artifacts,*,run,logs,certificate):
    """Publish already acquired public data below the bound artifact directory."""
    from .manifest import _open_root
    from .security_license_acquisition import _write
    if any(not isinstance(body,bytes) or not body or len(body)>MAX_INDEX_BYTES for body in (run,logs,certificate)):
        fail('artifact-size','retained build data is empty or exceeds the metadata budget')
    root=Path(artifacts);root.mkdir(parents=True,exist_ok=True,mode=0o700);root,fd=_open_root(root)
    if not isinstance(fd,int):fail('artifact-platform','build data publication requires a qualified POSIX reader')
    def save(body):
        digest=hashlib.sha256(body).hexdigest();path='proofs/'+digest
        _write(fd,path,body,immutable=True)
        return {'path':path,'sha256':digest}
    try:
        manifest={'schema_version':1,'kind':'opengrep-public-build-provenance','source_commit':COMMIT,
            'run':save(run),'logs':save(logs),'certificate':save(certificate)}
        descriptor=save(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode())
        read_build_provenance(root,descriptor)
        return descriptor
    finally:os.close(fd)
