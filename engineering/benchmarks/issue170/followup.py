"""Keep first failures; rerun only corrected measurement and missing-dependency stages."""
import hashlib,json,os,pathlib,shutil,subprocess,time
R=pathlib.Path('/work'); A=R/'artifacts'
ENV={**os.environ,'GETZILLA_HOME':'/core','PYTHONPATH':'/input/src','PYTEST_ADDOPTS':'-p no:cacheprovider'}
metrics=json.loads((A/'metrics.json').read_text())
for name in ['index-summary.json','top20.json','pairs.csv','neighbors.json','vectors.npy']:
    shutil.copyfile(A/name,A/('initial-'+name))
def run(name,args,cwd='/work'):
    start=time.monotonic()
    env=dict(ENV)
    if cwd=='/work/candidate': env['PYTHONPATH']='/work/candidate/src'
    with (A/f'{name}.stdout').open('w') as out,(A/f'{name}.stderr').open('w') as err:
        p=subprocess.run(['/usr/bin/time','-v','-o',str(A/f'{name}.time'),*args],stdout=out,stderr=err,cwd=cwd,env=env,timeout=180)
    metrics.append({'stage':name,'argv':args,'cwd':cwd,'exit_code':p.returncode,'wall_seconds':time.monotonic()-start})
    (A/'metrics.json').write_text(json.dumps(metrics,indent=2)+'\n'); print(name,p.returncode,flush=True)
run('versions-final',['sh','-c','pip freeze; sha256sum /wheels/*'])
run('index-corrected',['python','/scripts/analyze.py'])
run('upstream-tests-final',['python','-m','pytest','-q','-o','addopts=','/input/tests'])
run('candidate-verify-final',['python','/core/scripts/getzilla_verify.py','--mode','fast','--no-record','--json'],cwd='/work/candidate')
run('candidate-final-git',['git','status','--porcelain=v1','--untracked-files=all'],cwd='/work/candidate')
manifest=json.loads((A/'source-manifest.json').read_text())
assert all(hashlib.sha256((pathlib.Path('/input')/p).read_bytes()).hexdigest()==h for p,h in manifest.items())
(A/'source-integrity-final.json').write_text(json.dumps({'files':len(manifest),'all_unchanged':True})+'\n')
