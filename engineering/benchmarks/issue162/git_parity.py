"""Read exact Git blobs independently of raw-file materialization."""
import hashlib,json,pathlib,subprocess,time
R=pathlib.Path(__file__).resolve().parent;repo=R/'upstream.git';logs=[]
def command(args):
    start=time.monotonic();p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    logs.append({'argv':args,'exit':p.returncode,'seconds':time.monotonic()-start,'stderr':p.stderr.decode(errors='replace')})
    if p.returncode:raise RuntimeError(p.stderr.decode())
    return p.stdout
if __name__=='__main__':
    try:
        if not repo.exists():
            command(['git','init','--bare',str(repo)])
            command(['git','--git-dir',str(repo),'fetch','--depth=1','https://github.com/pallets/itsdangerous.git','096c8d42545d3b68ea21a4f890fb2b2d8979c0bd'])
        report=[]
        for corpus in ('small','large'):
            manifest=json.loads((R/'data'/f'{corpus}-manifest.json').read_text());files=[]
            for row in manifest['files']:
                if not row['candidate']:continue
                args=['git','--git-dir',str(repo)] if corpus=='small' else ['git','-C','/home/pall/projects/getzilla']
                data=command([*args,'show',f'{manifest["commit"]}:{row["path"]}'])
                digest=hashlib.sha256(data).hexdigest();assert digest==row['sha256']
                assert (R/'gitless'/corpus/row['path']).read_bytes()==data
                files.append({'path':row['path'],'sha256':digest,'raw_gitless_git_object_equal':True})
            report.append({'corpus':corpus,'commit':manifest['commit'],'files':files})
        license_data=command(['git','-C','/home/pall/projects/getzilla','show','8352756ccddbb7b9f13da2da689ef633d968e30f:LICENSE'])
        (R/'support/large/LICENSE').write_bytes(license_data)
        (R/'results/git-object-parity.json').write_text(json.dumps(report,indent=2)+'\n')
    finally:(R/'execution/git-object-parity-commands.json').write_text(json.dumps(logs,indent=2)+'\n')
