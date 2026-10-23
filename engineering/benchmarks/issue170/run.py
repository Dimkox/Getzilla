"""Run offline stages inside a bounded container; preserve actual failure output."""
import concurrent.futures,hashlib,json,os,pathlib,subprocess,time,threading,sys,shutil
R=pathlib.Path('/work'); A=R/'artifacts'; A.mkdir(exist_ok=True)
ENV={**os.environ,'GETZILLA_HOME':'/core','GIT_AUTHOR_NAME':'Issue170 benchmark','GIT_AUTHOR_EMAIL':'benchmark@example.invalid','GIT_COMMITTER_NAME':'Issue170 benchmark','GIT_COMMITTER_EMAIL':'benchmark@example.invalid','PYTHONPATH':'/input/src','PYTEST_ADDOPTS':'-p no:cacheprovider'}
metrics=[]
lock=threading.Lock()
def run(name,args,cwd='/work',timeout=240):
    start=time.monotonic()
    with (A/f'{name}.stdout').open('w') as out,(A/f'{name}.stderr').open('w') as err:
        try:
            p=subprocess.run(['/usr/bin/time','-v','-o',str(A/f'{name}.time'),*args],cwd=cwd,env=ENV,stdout=out,stderr=err,timeout=timeout)
            code=p.returncode
        except subprocess.TimeoutExpired: code=124
    m={'stage':name,'argv':args,'cwd':cwd,'exit_code':code,'wall_seconds':time.monotonic()-start}
    with lock:
        metrics.append(m); (A/'metrics.json').write_text(json.dumps(metrics,indent=2)+'\n'); print(json.dumps(m),flush=True)
    return code
run('versions',['sh','-c','python --version; git --version; node --version; /tools/node_modules/.bin/jscpd --version; pip freeze; dpkg-query -W; sha256sum /wheels/*'])
shutil.copyfile('/tools/package-lock.json',A/'npm-package-lock.json')
run('jscpd-help',['/tools/node_modules/.bin/jscpd','--help'])
run('core-plan',['python','/core/scripts/adopt_existing.py','plan','--source','/input','--target','/work/candidate','--output','/work/artifacts/plan.json','--state-root','/work/adoption-state'])
if (A/'plan.json').exists():
    plan=json.loads((A/'plan.json').read_text())
    run('core-apply',['python','/core/scripts/adopt_existing.py','apply','--plan','/work/artifacts/plan.json','--plan-digest',plan['plan_id'],'--writers-stopped','--state-root','/work/adoption-state'])
if (R/'candidate/.git').exists():
    run('candidate-git',['git','log','--format=fuller','--stat'],cwd='/work/candidate')
    original=json.loads((A/'source-manifest.json').read_text())
    actual={str(p.relative_to(R/'candidate')):hashlib.sha256(p.read_bytes()).hexdigest() for p in (R/'candidate').rglob('*') if p.is_file() and '.git' not in p.relative_to(R/'candidate').parts}
    (A/'adoption-files.json').write_text(json.dumps({'original_unchanged':all(actual.get(k)==v for k,v in original.items()),'original_count':len(original),'candidate_count':len(actual),'added':{k:v for k,v in actual.items() if k not in original}},indent=2)+'\n')
    sys.path.insert(0,'/core/.getzilla')
    from getzilla.source_managed_layer import payload_entries
    entries=payload_entries(pathlib.Path('/core'))
    checks=[{'path':e.path,'expected_sha256':hashlib.sha256(e.content).hexdigest(),'matches':actual.get(e.path)==hashlib.sha256(e.content).hexdigest(),'mode_matches':bool((R/'candidate'/e.path).stat().st_mode&0o111)==(e.mode=='100755')} for e in entries]
    (A/'payload-validation.json').write_text(json.dumps({'expected_files':len(checks),'all_match':all(c['matches'] and c['mode_matches'] for c in checks),'entries':checks},indent=2)+'\n')
    run('candidate-verify',['python','/core/scripts/getzilla_verify.py','--mode','fast','--no-record','--json'],cwd='/work/candidate',timeout=240)
jobs=[('graph-build',['python','/core/scripts/getzilla_graph.py','build','--root','/input','--cache','/work/artifacts/source-graph.sqlite']),('index',['python','/scripts/analyze.py']),('upstream-tests',['python','-m','pytest','-q','-o','addopts=','/input/tests'])]
for minimum in (10,5):
    jobs.append((f'jscpd-{minimum}',['/tools/node_modules/.bin/jscpd','--min-lines',str(minimum),'--min-tokens','50','--format','python','--mode','mild','--reporters','json','--output',f'/work/artifacts/jscpd-{minimum}','/input/src','/input/tests']))
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
    list(pool.map(lambda j:run(*j),jobs))
run('graph-export',['python','/core/scripts/getzilla_graph.py','export','--root','/input','--cache','/work/artifacts/source-graph.sqlite'])
original=json.loads((A/'source-manifest.json').read_text())
assert all(hashlib.sha256((pathlib.Path('/input')/k).read_bytes()).hexdigest()==v for k,v in original.items())
(A/'source-integrity-final.json').write_text(json.dumps({'files':len(original),'all_unchanged':True})+'\n')
