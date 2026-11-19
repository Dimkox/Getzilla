import pathlib,sys,hashlib,tempfile,importlib.util
R=pathlib.Path(__file__).resolve().parent;C=R/'candidate';original=(C/'trusted_read.py').read_text()
def h(b):return hashlib.sha256(b).hexdigest()
def check(text,kind):
 ns={};exec(compile(text,'scratch-reader','exec'),ns)
 with tempfile.TemporaryDirectory(dir=R) as tmp:
  root=pathlib.Path(tmp);(root/'real').mkdir();data=b'first\nsecond\n';(root/'real'/'a.py').write_bytes(data)
  hit={'tenant':'t','repository':'r','path':'real/a.py','file_sha256':h(data),'start':1,'end':1,'sha256':h(b'first\n')};allowed={'real/a.py'}
  if kind=='file_hash':(root/'real'/'a.py').write_bytes(b'first\nCHANGED\n')
  if kind=='allowlist':allowed=set()
  if kind=='symlink':
   (root/'link').symlink_to('real',target_is_directory=True);hit['path']='link/a.py';allowed={'link/a.py'}
  try:ns['read_hit'](root,hit,'t','r',allowed);return 'accepted'
  except ValueError:return 'rejected'
for kind,a,b in [
 ('file_hash',"if hashlib.sha256(data).hexdigest()!=hit['file_sha256']:raise ValueError('stale')","if False:raise ValueError('stale')"),
 ('allowlist','or str(path) not in allowed',''),
 ('symlink',"if candidate.is_symlink():raise ValueError('symlink')","if False:raise ValueError('symlink')")]:
 baseline=check(original,kind);mutant=check(original.replace(a,b),kind)
 assert (baseline,mutant)==('rejected','accepted')
 print(kind,'baseline rejected; mutant accepted; supplemental control KILLED')
S=R.parent/'issue162-20261023T2227'
import json
for corpus in ('small','large'):
 m=json.loads((C/'data'/f'{corpus}-manifest.json').read_text())
 for f in m['files']:
  p=S/('sources' if f['candidate'] else 'support')/corpus/f['path'];assert h(p.read_bytes())==f['sha256']
 print(corpus,'all source/support hashes verified')
for p in json.loads((C/'data/model-pins.json').read_text()):assert h((S/'model'/p['path']).read_bytes())==p['sha256']
print('all retained model hashes verified')
for corpus in ('small','large'):
 snippets=json.loads((C/'data/qrel-source-snippets.json').read_text());sample=next(x for x in snippets if x['corpus']==corpus)
 source=(S/'sources'/corpus/sample['path']).read_bytes().splitlines(keepends=True)
 assert b''.join(source[sample['start']-1:sample['end']]).decode()==sample['source']
 print('sample span',corpus,sample['id'],repr(sample['source'][:350]))
P=S/'publication';manifest=json.loads((P/'SHA256SUMS.json').read_text())
assert all(h((P/n).read_bytes())==v for n,v in manifest.items())
assert {str(p.relative_to(P)) for p in P.rglob('*') if p.is_file() and p.name!='SHA256SUMS.json'}==set(manifest)
print('final publication manifest',h((P/'SHA256SUMS.json').read_bytes()),'files',len(manifest),'bytes',sum(p.stat().st_size for p in P.rglob('*') if p.is_file()))
