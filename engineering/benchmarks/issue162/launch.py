"""Run only owned containers; each command and exit is retained."""
import concurrent.futures,hashlib,json,os,pathlib,shutil,subprocess,time
R=pathlib.Path(__file__).resolve().parent;E=R/'execution';E.mkdir(exist_ok=True)
IMAGE='getzilla-issue162-tools:local'
def command(name,args):
    start=time.monotonic();p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    (E/f'{name}.stdout').write_bytes(p.stdout);(E/f'{name}.stderr').write_bytes(p.stderr)
    record={'argv':args,'exit_code':p.returncode,'seconds':time.monotonic()-start}
    (E/f'{name}.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'stage':name,**record}),flush=True)
    if p.returncode:raise RuntimeError(name)
    return p.stdout
def base(name,network='none'):
    return ['docker','run','--rm','--name',f'getzilla-issue162-{name}','--network',network,'--cpus','1','--memory','4g','--pids-limit','128','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--user',f'{os.getuid()}:{os.getgid()}','-v',f'{R}/data:/work/data:ro','-v',f'{R}/results:/work/results:rw','-v',f'{R}:/scripts:ro','-v',f'{R}/sources:/sources:ro','-v',f'{R}/gitless:/gitless:ro','-v',f'{R}/model:/model:ro','-v',f'{R}/codec:/codec:ro']
def prepare():
    for name in ('gitless','codec','results'): (R/name).mkdir(exist_ok=True)
    for corpus in ('small','large'):
        shutil.copytree(R/'sources'/corpus,R/'gitless'/corpus,dirs_exist_ok=True)
    command('image', ['docker','image','inspect',IMAGE,'--format','{{json .Id}}'])
    args=base('codec','bridge');args[-1]=f'{R}/codec:/codec:rw'
    args[args.index(f'{R}/data:/work/data:ro')]=f'{R}/data:/work/data:rw'
    command('codec',args+[IMAGE,'python','/scripts/prepare_codec.py'])
    command('packages',base('packages')+[IMAGE,'pip','freeze'])
    command('capacity',base('capacity')+[IMAGE,'python','/scripts/observe.py'])
def run():
    assert (R/'data/seal.json').exists(),'independent review seal required'
    # Two one-CPU containers maximum; parent reserves the remaining CPU capacity.
    tasks=[('small',['python','/scripts/benchmark.py','small']),('large',['python','/scripts/benchmark.py','large'])]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(lambda x:command(x[0],base(x[0])+[IMAGE,*x[1]]),tasks))
    # Cold loads use new processes and no source index reuse.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(lambda i:command(f'cold{i}',base(f'cold{i}')+[IMAGE,'python','/scripts/benchmark.py','cold']),range(3)))
if __name__=='__main__':
    import sys
    prepare() if sys.argv[1]=='prepare' else run()
