"""Materialize explicit pinned blobs. This script does not rank or index source."""
import ast, concurrent.futures, hashlib, json, pathlib, subprocess, urllib.request
ROOT = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path('/home/pall/projects/getzilla')
SMALL = '096c8d42545d3b68ea21a4f890fb2b2d8979c0bd'
LARGE = '8352756ccddbb7b9f13da2da689ef633d968e30f'
def sha(b): return hashlib.sha256(b).hexdigest()
def save(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n')
def git(*args): return subprocess.check_output(['git',*args], cwd=REPO)
def small_file(path):
    url=f'https://raw.githubusercontent.com/pallets/itsdangerous/{SMALL}/{path}'
    with urllib.request.urlopen(url,timeout=90) as r: data=r.read()
    return path,data,{'url':url,'mode':'100644'}
def inventory(name, entries, commit):
    manifest=[]; functions=[]
    for path,data,origin in sorted(entries):
        support=path.startswith('tests/') or path=='LICENSE.txt'
        target=ROOT/('support' if support else 'sources')/name/path
        target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data)
        row={'path':path,'sha256':sha(data),'bytes':len(data),'lines':len(data.splitlines()),'candidate':not support,**origin}
        manifest.append(row)
        if support: continue
        tree=ast.parse(data, filename=path)
        def visit(node,parents=()):
            for child in ast.iter_child_nodes(node):
                if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                    names=parents+(child.name,)
                    if not isinstance(child,ast.ClassDef):
                        start=min([child.lineno]+[d.lineno for d in child.decorator_list]); end=child.end_lineno
                        text=b''.join(data.splitlines(keepends=True)[start-1:end])
                        overload=any(isinstance(d,ast.Name) and d.id=='overload' or isinstance(d,ast.Attribute) and d.attr=='overload' for d in child.decorator_list)
                        functions.append({'id':f'{path}:{start}:{".".join(names)}','path':path,'symbol':'.'.join(names),'start':start,'end':end,'sha256':sha(text),'file_sha256':sha(data),'overload_stub':overload})
                    visit(child,names)
                else: visit(child,parents)
        visit(tree)
    snapshot=sha(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode())
    save(ROOT/'data'/f'{name}-manifest.json',{'corpus':name,'commit':commit,'snapshot_sha256':snapshot,'files':manifest})
    save(ROOT/'data'/f'{name}-functions.json',functions)
    return {'corpus':name,'files':sum(x['candidate'] for x in manifest),'functions':len(functions),'snapshot_sha256':snapshot}
def main():
    paths=['src/itsdangerous/'+p+'.py' for p in ('__init__','_json','encoding','exc','serializer','signer','timed','url_safe')]
    paths += ['tests/test_itsdangerous/'+p+'.py' for p in ('__init__','test_encoding','test_serializer','test_signer','test_timed','test_url_safe')]
    paths += ['LICENSE.txt']
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: small=list(pool.map(small_file,paths))
    entries=[]
    for line in git('ls-tree','-r',LARGE,'.getzilla/getzilla','scripts').decode().splitlines():
        meta,path=line.split('\t'); mode,kind,blob=meta.split()
        if mode not in ('100644','100755') or kind!='blob' or not path.endswith('.py'): continue
        if not (path.startswith('.getzilla/getzilla/') or path.startswith('scripts/')): continue
        if any(p in ('tests','fixtures','vendor','__pycache__') for p in pathlib.PurePosixPath(path).parts): continue
        entries.append((path,git('show',f'{LARGE}:{path}'),{'mode':mode,'git_blob':blob}))
    for path in ['tests/test_code_graph_incremental.py','tests/test_code_graph_store.py','tests/test_code_graph_e2e.py','tests/test_factory_v15_context_schema.py']:
        entries.append((path,git('show',f'{LARGE}:{path}'),{'mode':'100644'}))
    results=[inventory('small',small,SMALL),inventory('large',entries,LARGE)]
    save(ROOT/'data/inventory-summary.json',results); print(json.dumps(results))
if __name__=='__main__': main()
