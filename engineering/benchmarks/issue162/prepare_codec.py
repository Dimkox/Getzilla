import hashlib,json,pathlib,tiktoken
r=pathlib.Path('/codec');r.mkdir(exist_ok=True)
codec=tiktoken.get_encoding('o200k_base')
assert codec.decode(codec.encode('source context'))=='source context'
rows=[{'path':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(r.iterdir()) if p.is_file()]
pathlib.Path('/work/data/codec-pins.json').write_text(json.dumps({'package':'tiktoken==0.12.0','encoding':'o200k_base','assets':rows},indent=2)+'\n')
