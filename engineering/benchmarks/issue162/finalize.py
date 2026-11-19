"""Summarize every fixed result; do not retune or relabel."""
import collections,csv,hashlib,json,pathlib,shutil,statistics,subprocess
R=pathlib.Path(__file__).resolve().parent;O=R/'results';P=R/'publication'
def load(p):return json.loads(p.read_text())
def write(p,o):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(o,indent=2,sort_keys=True)+'\n')
def main():
    summaries=[];paired=[];allrows=[]
    for corpus in ('small','large'):
        rows=load(O/f'{corpus}-results.json');positives=[r for r in rows if 'metrics' in r]
        for arm in ('exact_symbol','bm25','semantic','rrf'):
            for kind in ('all','exact','behavior','boundary','multi'):
                group=[r for r in positives if r['arm']==arm and (kind=='all' or r['class']==kind)]
                summaries.append({'corpus':corpus,'arm':arm,'class':kind,'queries':len(group),**{key:statistics.mean(r['metrics'][key] for r in group) for key in group[0]['metrics']}})
        for row in rows:
            allrows.append({'corpus':corpus,'query':row['query'],'class':row['class'],'arm':row['arm'],**row.get('metrics',{}),'returned':len(row['rankings'])})
        byquery=collections.defaultdict(dict)
        for row in positives:byquery[row['query']][row['arm']]=row['metrics']
        for query,arms in byquery.items():
            for baseline in ('exact_symbol','bm25','semantic'):
                paired.append({'corpus':corpus,'query':query,'comparison':f'rrf_minus_{baseline}',**{k:arms['rrf'][k]-arms[baseline][k] for k in arms['rrf']}})
    write(O/'summary.json',summaries);write(O/'paired-differences.json',paired)
    envelopes={}
    for corpus in ('small','large'):
        manifest=load(R/'data'/f'{corpus}-manifest.json')
        envelopes[corpus]={'corpus_id':corpus,'tenant':'benchmark','repository':corpus,'source_commit':manifest['commit'],'snapshot_sha256':manifest['snapshot_sha256'],'index_schema':'issue162-v1','config_sha256':hashlib.sha256((R/'data/config.json').read_bytes()).hexdigest(),'model_revision':'1110a243fdf4706b3f48f1d95db1a4f5529b4d41','result_file':f'{corpus}-results.json','result_sha256':hashlib.sha256((O/f'{corpus}-results.json').read_bytes()).hexdigest(),'citation_binding':'Every row and hit in result_file inherits this envelope. Hit file/range/chunk hashes remain explicit. Component scores are separate; RRF is not confidence.'}
    write(O/'result-envelopes.json',envelopes)
    inventory_counts=[]
    for corpus in ('small','large'):
        manifest=load(R/'data'/f'{corpus}-manifest.json');files=[f for f in manifest['files'] if f['candidate']]
        declarations=load(R/'data'/f'{corpus}-functions.json')
        inventory_counts.append({'corpus':corpus,'candidate_files':len(files),'source_lines':sum(f['lines'] for f in files),'source_bytes':sum(f['bytes'] for f in files),'ast_function_declarations':len(declarations),'decorated_overload_stubs':sum(f['overload_stub'] for f in declarations),'indexed_windows':load(O/f'{corpus}-metrics.json')['chunks']})
    write(O/'inventory-counts.json',inventory_counts)
    for name,rows in [('summary',summaries),('per-query',allrows),('paired-differences',paired)]:
        keys=list(dict.fromkeys(k for row in rows for k in row))
        with (O/f'{name}.csv').open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(rows)
    disk={name:sum(p.stat().st_size for p in (R/name).rglob('*') if p.is_file()) for name in ('model','codec','sources','gitless','results','data')}
    write(O/'disk-bytes.json',disk)
    lines=['# Fixed source retrieval experiment, issue 162','', 'The experiment ran actual local embeddings and all four fixed retrieval arms. It changes no installed product source. The tables describe recall against registered qrels only. They do not establish universal retrieval recall or broad superiority.','', '## Inputs and gate','', 'Small: itsdangerous 2.2.0 at `096c8d42545d3b68ea21a4f890fb2b2d8979c0bd`, eight Python source files. Large: Getzilla at `8352756ccddbb7b9f13da2da689ef633d968e30f`, 140 approved Python runtime/script files. This is a bounded source scope inside the large repository. It is not whole-repository coverage. Separate documentation, tests, packages, fixtures and generated mirrors are not candidates. Source docstrings remain code bytes. Tests are retained separately for source review.','', 'Each corpus has 16 positive questions: four exact-symbol, four behavior, four boundary and four multi-function questions. Four no-answer controls are separate. The selected independent repo explorer checked source spans, hashes, identities and non-overload labels before any ranking. `data/seal.json` binds the unchanged manifest, query, qrel and config bytes. Large questions concentrate on graph and ingestion behavior. Other retrieved hits remain unjudged.','', '## Registered-qrel quality','', '| Corpus | Arm | Function R@1 | R@5 | R@10 | R@20 | MRR@10 | Budget 2048 recall | Budget 8192 recall |','| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for s in summaries:
        if s['class']!='all':continue
        vals=[s[f'function_recall@{k}'] for k in (1,5,10,20)]+[s['mrr@10'],s['budget_2048_recall'],s['budget_8192_recall']]
        lines.append('| '+s['corpus']+' | '+s['arm']+' | '+' | '.join(f'{v:.3f}' for v in vals)+' |')
    lines+=['','`results/summary.csv` includes file recall and query-class slices. `per-query.csv`, `paired-differences.csv` and the full result JSON preserve each question, failure and top-100 list. A function counts once even if several windows occur. File metrics deduplicate paths. Budget recall means that at least one window from a registered function fit in the packed context. It does not prove that the complete answer or all relevant lines fit. Overlap lines are included once. Citation headers, included line labels, separators and source text count toward the pinned o200k_base context proxy. These counts are not measured LLM billing. Encoder token counts are separate.','', '## Runtime and storage','', '| Corpus | Functions | Windows | Truncated windows | Model load s | Index build s | Peak RSS KiB | Semantic warm p50 ms | Semantic warm p95 ms |','| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for corpus in ('small','large'):
        m=load(O/f'{corpus}-metrics.json');lat=m['latency_summary']['semantic_end_to_end_ms']
        lines.append(f"| {corpus} | {m['functions']} | {m['chunks']} | {m['encoder_truncated_chunks']} | {m['cold_model_load_seconds']:.3f} | {m['index_build_seconds']:.3f} | {m['peak_rss_kib']} | {lat['median']:.3f} | {lat['p95']:.3f} |")
    cold=[load(R/'execution'/f'cold{i}.stdout') for i in range(3)]
    lines+=['',f"Three fresh-process model loads took {', '.join(f'{r["cold_model_load_seconds"]:.3f}' for r in cold)} seconds. These are process-cold, not guaranteed cold OS page-cache loads. Warm timing uses ten passes over all questions. Query embedding time is included in semantic and RRF end-to-end figures. Ranking-only and query-embedding figures remain separate in timing JSON. BM25 and symbol latency do not include an unnecessary model call. Peak RSS covers the process, including later parity checks; it is not a baseline-subtracted allocation.",'',f"Measured bytes: model assets {disk['model']:,}; codec cache {disk['codec']:,}; source view {disk['sources']:,}; duplicate Gitless view {disk['gitless']:,}; result artifacts {disk['results']:,}. The full ONNX model is 90,405,214 bytes, verified against its pinned SHA256. Source-window vectors are stored as float32. Package versions, image identity and exact commands are retained. The image dependency installation pins the four direct packages; transitive versions are captured in `execution/packages.stdout` but not individually resolver-locked. Image bytes are identified by digest. The compact publication excludes models, tool caches, duplicate source trees and vectors.",'', '## Controls and limits','', 'The experimental trusted reader passed stale-file, deleted-file, rename, forged-range, chunk-hash, tenant, repository, path-filter, traversal and symlink controls. The first characterization run failed because the reader module did not exist. The later run passed eleven tests. The reader operates on read-only offline source mounts. It is not a production sandbox and does not claim protection from hostile concurrent replacement of parent directories.','', 'Every stored chunk was read again with its file hash, range and chunk hash. Direct pinned Git-object bytes, raw/copied source bytes and the independent Gitless view match. Re-encoding the Gitless view produced identical rankings. The inference containers had no Git dependency or Git ancestor. Declared upstream commits remain provenance; copied-byte manifests establish snapshot identity.','', 'No-answer controls report candidate return counts and raw scores separately in full result JSON. Semantic ranking always returns candidates. No calibrated abstention threshold was fitted. These controls do not prove that retrieval can decide answerability. Pinned large-corpus absence judgments remain valid at 8352756 even if later product work adds a jscpd adapter.','', 'Quality comes from one deterministic ranking. Ten warm repetitions measure timing only. Parameters and qrels were not tuned after ranking. The corpus is Python only. AST function chunks omit standalone module/class-only content from ranked candidates. Nested functions may overlap outer bodies. The English generic MiniLM model was not trained here for code. Line windows can separate useful evidence. Unjudged hits are not known false positives. The small curated set does not support statistical or cross-language claims.','', 'Offline inference used two one-CPU containers at most, one ORT thread each, a read-only root, dropped capabilities, no-new-privileges, bounded memory and processes, and no network. Network preparation downloaded only fixed model/tool/source assets. No source was uploaded. External scan/index LLM calls and tokens: zero. Orchestration model usage: unmeasured (`null`).','', '## Decision and next step','', 'Keep exact symbols and BM25 as cheap explicit components. Treat local embeddings and RRF as optional candidates for a later prototype. Assess the paired per-query evidence before selecting defaults. Preserve component ranks and exact citation bytes. Expand blind labels across more tasks and repositories before any general claim. `design.md` records the contract, lifecycle, tradeoffs, future implementation steps and rollback. No product PR, merge, release or production operation is part of this research contour.']
    lines += ['', 'Timing notes: semantic and RRF end-to-end fields sum the measured embedding and required component intervals. `all_arms_end_to_end_ms` records the full measured wall interval. The warm passes use a fixed arm order on a shared host with other bounded work. CPU quota is one per container; CPU affinity is not pinned to a private core. Treat these latency values as observations for this environment. Recall@k takes the first k distinct functions or files after window ranking, within the retained top-100 window list. No confidence interval or broad significance claim is made.', '', 'References: https://www.dobryakov.com/howto/book-as-context.html and https://www.dobryakov.com/howto/hybrid-search.html motivated source provenance and complementary signals. They are not evidence that this model or these fusion weights work best for code. No book corpus was downloaded or indexed.']
    report='\n'.join(lines).replace('passed eleven tests','passed twelve tests')
    report += '\nFive separate metric controls passed for recall arithmetic, context-window deduplication, hard budgets, exact symbol matching and identifier tokenization. A directory-as-file negative control is included in the twelve reader tests.\n'
    report += '\nCandidate-kind limit: the extractor excludes decorated overload stubs, but retains other AST functions, including the small corpus protocol declarations `_PDataSerializer.loads` and `_PDataSerializer.dumps`. Thus function counts mean non-overload AST candidates, not exclusively executable implementations. Positive qrels point only to implementations. The retained declarations were not removed after ranking. A later experiment should preregister a separate declaration category.\n'
    report += '\nExact source counts: '+ '; '.join(f"{c['corpus']}: {c['candidate_files']} files, {c['source_lines']:,} physical lines, {c['source_bytes']:,} bytes, {c['ast_function_declarations']} AST function declarations, {c['decorated_overload_stubs']} decorated overload stubs, {c['indexed_windows']} windows" for c in inventory_counts)+'.\n'
    (R/'report.md').write_text(report+'\n')
    P.mkdir(exist_ok=True)
    for name in ['report.md','design.md','decisions.md','mistakes.md','REPRODUCE.md','prepare.py','make_qrels.py','prepare_model.py','prepare_codec.py','seal.py','benchmark.py','trusted_read.py','test_contract.py','test_metrics.py','run_metric_controls.py','launch.py','git_parity.py','finalize.py','check_artifacts.py','check_publication.py','observe.py','capture_capacity.py','Dockerfile','Dockerfile.replay']:
        shutil.copy2(R/name,P/name)
    for name in ('data','execution'):
        shutil.copytree(R/name,P/name,dirs_exist_ok=True)
    shutil.copytree(R/'support',P/'support',dirs_exist_ok=True)
    review=R.parent/'issue162-qrel-review.md'
    if review.exists():shutil.copy2(review,P/'qrel-review.md')
    for p in O.iterdir():
        if p.suffix=='.npy' or p.name.endswith('-chunks.json'):continue
        dest=P/'results'/p.name;dest.parent.mkdir(exist_ok=True);shutil.copy2(p,dest)
    snippets=[]
    for corpus in ('small','large'):
        seen=set()
        for q in load(R/'data'/f'{corpus}-qrels.json')['queries']:
            for f in q['qrels']:
                if f['id'] in seen:continue
                seen.add(f['id']);data=(R/'sources'/corpus/f['path']).read_bytes();text=b''.join(data.splitlines(keepends=True)[f['start']-1:f['end']]).decode()
                snippets.append({'corpus':corpus,**f,'source':text})
    write(P/'data/qrel-source-snippets.json',snippets)
    for corpus,file in [('small','LICENSE.txt'),('large','LICENSE')]:
        target=P/'licenses'/corpus/file;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(R/'support'/corpus/file,target)
    hashes={str(p.relative_to(P)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(P.rglob('*')) if p.is_file() and p.name!='SHA256SUMS.json'}
    write(P/'SHA256SUMS.json',hashes)
    print(json.dumps({'publication':str(P),'files':len(hashes),'bytes':sum(p.stat().st_size for p in P.rglob('*') if p.is_file())}))
if __name__=='__main__':main()
