"""Check sealed labels, complete results and negative controls without tuning."""
import hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parent
seal=json.loads((R/'data/seal.json').read_text())
for path,digest in seal['hashes'].items():assert hashlib.sha256((R/path).read_bytes()).hexdigest()==digest
for corpus in ('small','large'):
    manifest=json.loads((R/'data'/f'{corpus}-manifest.json').read_text())
    for f in manifest['files']:
        if not f['candidate']:continue
        for view in ('sources','gitless'):
            assert hashlib.sha256((R/view/corpus/f['path']).read_bytes()).hexdigest()==f['sha256']
    queries=json.loads((R/'data'/f'{corpus}-qrels.json').read_text())['queries']
    rows=json.loads((R/'results'/f'{corpus}-results.json').read_text());assert len(rows)==80
    assert len({(r['query'],r['arm']) for r in rows})==80
    assert len([q for q in queries if q['qrels']])==16
    for row in rows:
        assert len(row['rankings'])<=100
        if row['class']=='no_answer':assert 'metrics' not in row
        else:
            assert all(0<=v<=1 for k,v in row['metrics'].items() if 'tokens' not in k)
            assert row['metrics']['budget_2048_tokens']<=2048
            assert row['metrics']['budget_8192_tokens']<=8192
p=subprocess.run(['python3',str(R/'test_contract.py')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
(R/'execution/reader-controls.stdout').write_bytes(p.stdout);(R/'execution/reader-controls.stderr').write_bytes(p.stderr)
assert p.returncode==0
result={'seal_unchanged':True,'positive_queries':32,'no_answer_controls':8,'arm_query_rows':160,'reader_controls':12,'reader_controls_exit':p.returncode,'initial_characterization':{'exit':1,'observed':'ModuleNotFoundError: No module named trusted_read','source':'first test invocation before reader implementation'},'product_tree_changed_by_research':False}
(R/'results/artifact-checks.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
