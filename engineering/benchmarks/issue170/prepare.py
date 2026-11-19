"""Download immutable benchmark inputs; never execute downloaded project code here."""
import hashlib, io, json, os, pathlib, subprocess, tarfile, urllib.request
ROOT = pathlib.Path(__file__).resolve().parent
SOURCE = '096c8d42545d3b68ea21a4f890fb2b2d8979c0bd'
CORE = '8352756ccddbb7b9f13da2da689ef633d968e30f'
MODEL = '1110a243fdf4706b3f48f1d95db1a4f5529b4d41'
def download(url, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with urllib.request.urlopen(url, timeout=120) as r, path.open('wb') as f:
            while block := r.read(1024*1024): f.write(block)
    return {'url':url, 'bytes':path.stat().st_size, 'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
def extract(blob, target, strip=False):
    target.mkdir(exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob)) as t:
        for m in t:
            parts=pathlib.PurePosixPath(m.name).parts
            if strip: parts=parts[1:]
            if not parts: continue
            if m.name.startswith('/') or '..' in parts or '.git' in parts or not (m.isfile() or m.isdir()):
                raise ValueError('unsafe archive member: '+m.name)
            p=target.joinpath(*parts)
            if m.isdir(): p.mkdir(parents=True,exist_ok=True)
            else:
                p.parent.mkdir(parents=True,exist_ok=True)
                p.write_bytes(t.extractfile(m).read())
                p.chmod(0o755 if m.mode & 0o111 else 0o644)
pins={}
archive=ROOT/'downloads/source.tar.gz'
pins['source']=download(f'https://codeload.github.com/pallets/itsdangerous/tar.gz/{SOURCE}',archive)
extract(archive.read_bytes(),ROOT/'original',True)
core=subprocess.check_output(['git','archive',CORE],cwd='/home/pall/projects/getzilla')
(ROOT/'downloads/core.tar').write_bytes(core)
extract(core,ROOT/'core')
pins['core']={'commit':CORE,'archive_sha256':hashlib.sha256(core).hexdigest()}
for name in ['onnx/model.onnx','tokenizer.json','tokenizer_config.json','config.json','special_tokens_map.json','vocab.txt','sentence_bert_config.json','1_Pooling/config.json']:
    pins[name]=download(f'https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/{MODEL}/{name}', ROOT/'model'/name)
assert pins['onnx/model.onnx']['bytes']==90405214
assert pins['onnx/model.onnx']['sha256']=='6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452'
manifest={str(p.relative_to(ROOT/'original')):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'original').rglob('*')) if p.is_file()}
(ROOT/'artifacts').mkdir(exist_ok=True)
(ROOT/'artifacts/source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(ROOT/'artifacts/input-pins.json').write_text(json.dumps(pins,indent=2)+'\n')
print(json.dumps({'source_files':len(manifest),'model_verified':True,'core':CORE}))
