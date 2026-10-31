"""Seal only after the parent reports independent qrel review PASS."""
import hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parent
hashes=json.loads((R/'data/pre-review-hashes.json').read_text())
for path,digest in hashes.items():assert hashlib.sha256((R/path).read_bytes()).hexdigest()==digest
seal={'independent_qrel_review':'pass','reviewer':'selected repo_explorer retrieval162_audit','authorization':'parent message: Independent qrel gate PASS; no corrections; authorize seal and execute','hashes':hashes,'limitations':['curated graph/ingestion questions in bounded large source scope','registered function qrels only; other hits unjudged','no answer controls do not establish semantic abstention'],'lifecycle_metadata':'Native SubagentStart child ID/generation unavailable; parent instructed no invented metadata.'}
(R/'data/seal.json').write_text(json.dumps(seal,indent=2)+'\n')
print(hashlib.sha256((R/'data/seal.json').read_bytes()).hexdigest())
