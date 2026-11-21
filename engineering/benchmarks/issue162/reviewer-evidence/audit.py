import pathlib,json,hashlib,subprocess,statistics,sys,shutil,os
S=pathlib.Path('/home/pall/projects/getzilla/.getzilla/runtime/scratch/issue162-20261023T2227/publication')
R=pathlib.Path(__file__).resolve().parent; C=R/'candidate'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def verify(p):
 m=json.loads((p/'SHA256SUMS.json').read_text());actual={str(x.relative_to(p)) for x in p.rglob('*') if x.is_file() and x.name!='SHA256SUMS.json'}
 assert actual==set(m),(actual-set(m),set(m)-actual)
 assert all(digest(p/n)==h for n,h in m.items())
 return digest(p/'SHA256SUMS.json')
print('source and copy manifest',verify(S),verify(C),flush=True)
print('scratch parent mode',oct(R.stat().st_mode&0o7777),'owner',R.stat().st_uid,flush=True)
for corpus in ('small','large'):
 qs=json.loads((C/'data'/f'{corpus}-qrels.json').read_text())['queries'];qmap={q['id']:q for q in qs};rows=json.loads((C/'results'/f'{corpus}-results.json').read_text())
 assert len(rows)==80 and len({(r['query'],r['arm']) for r in rows})==80
 for r in rows:
  q=qmap[r['query']]
  if not q['qrels']:continue
  for field,key in [('function','function_id'),('file','path')]:
   rel={x['id' if field=='function' else 'path'] for x in q['qrels']};seen=[]
   for x in r['rankings']:
    if x[key] not in seen:seen.append(x[key])
   for k in (1,5,10,20):assert r['metrics'][f'{field}_recall@{k}']==len(rel&set(seen[:k]))/len(rel)
  rel={x['id'] for x in q['qrels']};seen=[]
  for x in r['rankings']:
   if x['function_id'] not in seen:seen.append(x['function_id'])
  assert r['metrics']['mrr@10']==next((1/i for i,f in enumerate(seen[:10],1) if f in rel),0)
 summary=json.loads((C/'results/summary.json').read_text())
 for s in summary:
  if s['corpus']!=corpus:continue
  group=[r for r in rows if 'metrics' in r and r['arm']==s['arm'] and (s['class']=='all' or s['class']==r['class'])]
  assert s['queries']==len(group)
  for k in group[0]['metrics']:assert s[k]==statistics.mean(r['metrics'][k] for r in group)
 print(corpus,'80 unique rows; recall, MRR, all summaries recomputed',flush=True)
env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}
def test():return subprocess.run([sys.executable,'test_contract.py'],cwd=C,env=env,capture_output=True,text=True)
p=test();print('baseline',p.returncode,p.stderr.strip(),flush=True);assert p.returncode==0
original=(C/'trusted_read.py').read_text()
mutants={
 'partition':("if hit['tenant']!=tenant or hit['repository']!=repository:raise ValueError('partition')","if False:raise ValueError('partition')"),
 'file_hash':("if hashlib.sha256(data).hexdigest()!=hit['file_sha256']:raise ValueError('stale')","if False:raise ValueError('stale')"),
 'chunk_hash':("if hashlib.sha256(chunk).hexdigest()!=hit['sha256']:raise ValueError('chunk')","if False:raise ValueError('chunk')"),
 'allowlist':("or str(path) not in allowed",""),
 'symlink':("if candidate.is_symlink():raise ValueError('symlink')","if False:raise ValueError('symlink')"),
 'range':("if type(start)!=int or type(end)!=int or not 1<=start<=end<=len(lines):raise ValueError('range')","if False:raise ValueError('range')")}
for name,(a,b) in mutants.items():
 assert a in original;(C/'trusted_read.py').write_text(original.replace(a,b));p=test();print('mutant',name,'killed' if p.returncode else 'SURVIVED',p.stderr.strip().splitlines()[-1],flush=True)
(C/'trusted_read.py').write_text(original)
print('source after',verify(S),flush=True)
