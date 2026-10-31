"""Verify the compact review candidate without changing it."""
import hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parent;P=R/'publication'
manifest=json.loads((P/'SHA256SUMS.json').read_text())
actual={str(p.relative_to(P)) for p in P.rglob('*') if p.is_file() and p.name!='SHA256SUMS.json'}
assert actual==set(manifest)
for name,digest in manifest.items():assert hashlib.sha256((P/name).read_bytes()).hexdigest()==digest,name
for corpus in ('small','large'):
    q=json.loads((P/'data'/f'{corpus}-qrels.json').read_text())['queries']
    assert len(q)==20
    metrics=json.loads((P/'results'/f'{corpus}-metrics.json').read_text())
    assert metrics['gitless']['rankings_equal'] and metrics['gitless']['bytes_and_ranges_equal']
result={'status':'frozen-for-independent-code-review','manifest_sha256':hashlib.sha256((P/'SHA256SUMS.json').read_bytes()).hexdigest(),'files':len(manifest),'bytes':sum(p.stat().st_size for p in P.rglob('*') if p.is_file()),'publication':str(P),'reviewed_qrels_seal_sha256':hashlib.sha256((P/'data/seal.json').read_bytes()).hexdigest(),'checks':'all file hashes, complete inventory, both qrel sets, both Gitless parity results'}
(R/'freeze.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
