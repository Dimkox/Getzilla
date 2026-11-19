"""Register source-grounded questions before any retrieval execution."""
import hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parent
S='src/itsdangerous/'
G='.getzilla/getzilla/'
rows={
'small':[
('exact','Locate base64_decode.', [('encoding.py','base64_decode')], 'Restores padding and wraps decoder errors.'),
('exact','Locate Signer.derive_key.', [('signer.py','Signer.derive_key')], 'Selects concat, django-concat, hmac or none.'),
('exact','Locate Serializer.iter_unsigners.', [('serializer.py','Serializer.iter_unsigners')], 'Yields configured and fallback signers.'),
('exact','Locate TimestampSigner.timestamp_to_datetime.', [('timed.py','TimestampSigner.timestamp_to_datetime')], 'Constructs an aware UTC datetime.'),
('behavior','Where does verification try the newest secret first and then older secrets?', [('signer.py','Signer.verify_signature')], 'Reverses secret_keys before verification.'),
('behavior','Where is a shorter compressed representation selected and marked with a leading dot?', [('url_safe.py','URLSafeSerializerMixin.dump_payload')], 'Compares compressed size and prefixes a dot.'),
('behavior','Where are decoded objects recovered from a damaged signature for debugging?', [('serializer.py','Serializer._loads_unsafe_impl')], 'Catches BadSignature and attempts payload decoding.'),
('behavior','Where are leading zero bytes removed from an encoded integer?', [('encoding.py','int_to_bytes')], 'Strips zero bytes from packed integer.'),
('boundary','Which constructor rejects a separator that can occur in the encoded signature alphabet?', [('signer.py','Signer.__init__')], 'Rejects separator membership in base64 alphabet.'),
('boundary','Where are both expired and future-dated signed values rejected?', [('timed.py','TimestampSigner.unsign')], 'Rejects age above max_age or below zero.'),
('boundary','Where does corrupt compressed payload data become a payload error?', [('url_safe.py','URLSafeSerializerMixin.load_payload')], 'Wraps zlib decode failures as BadPayload.'),
('boundary','Where does a missing signature separator raise an error before verification?', [('signer.py','Signer.unsign')], 'Checks separator before rsplit.'),
('multi','Trace object serialization through signing and final text conversion.', [('serializer.py','Serializer.dumps'),('serializer.py','Serializer.dump_payload'),('serializer.py','Serializer.make_signer'),('signer.py','Signer.sign')], 'Caller transforms object then creates signer and signs bytes.'),
('multi','Trace timestamp attachment from integer time through byte conversion and URL encoding.', [('timed.py','TimestampSigner.sign'),('timed.py','TimestampSigner.get_timestamp'),('encoding.py','int_to_bytes'),('encoding.py','base64_encode')], 'Explicit timestamp conversion call chain.'),
('multi','Trace signature checking from splitting a signed value through constant-time algorithm comparison.', [('signer.py','Signer.unsign'),('signer.py','Signer.verify_signature'),('signer.py','SigningAlgorithm.verify_signature')], 'Unsign calls verifier, which calls algorithm compare_digest.'),
('multi','Trace timed object loading with fallback signers and immediate expiry propagation.', [('timed.py','TimedSerializer.loads'),('timed.py','TimedSerializer.iter_unsigners'),('serializer.py','Serializer.iter_unsigners'),('timed.py','TimestampSigner.unsign')], 'Timed loader forwards age and stops on expiry.'),
],
'large':[
('exact','Locate change_set in code_graph.incremental.', [('code_graph/incremental.py','change_set')], 'Computes added/deleted/modified path digests.'),
('exact','Locate GraphStore.publish.', [('code_graph/store.py','GraphStore.publish')], 'Transactionally stores generation and active pointer.'),
('exact','Locate parse_python in code_graph.python_parser.', [('code_graph/python_parser.py','parse_python')], 'Bounded AST parser entry point.'),
('exact','Locate route_ingestion.', [('project_ingestion.py','route_ingestion')], 'Dispatches folder versus Git ingestion.'),
('behavior','Where are unchanged parsed files reused while all relationships are rebuilt?', [('code_graph/incremental.py','update_index')], 'Reuse dictionary passes unchanged parsed files to builder.'),
('behavior','Where does traversal follow both old and new reverse dependencies after a deletion?', [('code_graph/impact.py','calculate_impact'),('code_graph/impact.py','_reverse_edges')], 'Generations include previous and current for reverse traversal.'),
('behavior','Where are runtime reflection and dynamic imports recorded as gaps without running source?', [('code_graph/python_parser.py','_Visitor.visit_Call')], 'AST call visitor marks REFLECTION and DYNAMIC_IMPORT.'),
('behavior','Where does a directory with no repository marker get a plan to adopt it?', [('project_ingestion.py','route_ingestion')], 'Folder branch returns zero_git_plan.'),
('boundary','Where does an inconsistent declared change list force a complete rebuild?', [('code_graph/incremental.py','update_index')], 'CHANGE_SET_INCONSISTENT selects build_generation without reuse.'),
('boundary','Where does a competing active-generation change abort publication?', [('code_graph/store.py','GraphStore.publish')], 'Expected active mismatch raises CONCURRENT_PUBLISH and rolls back.'),
('boundary','Where are oversized files and syntax errors reported as incomplete rather than empty success?', [('code_graph/python_parser.py','parse_python')], 'FILE_OVER_GRAPH_LIMIT and SYNTAX_ERROR return incomplete.'),
('boundary','Where is a folder inside a parent repository blocked instead of treated as a standalone input?', [('project_ingestion.py','route_ingestion'),('project_ingestion.py','enclosing_worktree')], 'Parent worktree triggers INSIDE_PARENT_GIT_WORKTREE.'),
('multi','Trace changed source digests through incremental rebuilding and transactional publication.', [('code_graph/incremental.py','change_set'),('code_graph/incremental.py','update_index'),('code_graph/store.py','GraphStore.publish')], 'Change set feeds reuse choice then publication.'),
('multi','Trace active generation reading through record reconstruction and digest verification.', [('code_graph/store.py','GraphStore.read_active'),('code_graph/store.py','GraphStore.read_generation'),('code_graph/store.py','generation_from_record')], 'Read active delegates and validates reconstructed generation.'),
('multi','Trace Python byte decoding, syntax parsing, and symbol-span extraction.', [('code_graph/python_parser.py','_decode'),('code_graph/python_parser.py','parse_python'),('code_graph/python_parser.py','_Visitor._symbol')], 'Encoding detection precedes AST visitor with spans.'),
('multi','Trace conservative impact widening from unresolved calls through reverse dependencies and required checks.', [('code_graph/impact.py','_gap_files'),('code_graph/impact.py','_reverse_edges'),('code_graph/impact.py','calculate_impact')], 'Gap files expand reverse closure; security_checks always required.'),
]}
neg={
'small':['Where are expired tokens revoked in a PostgreSQL table?','Which function encrypts payloads with AES-GCM?','Where does HTTP middleware authenticate a browser cookie?','Which asynchronous worker refreshes signing keys from a cloud secret manager?'],
'large':['Which native semantic search endpoint reranks code with a cross encoder?','Where does a native BM25 index tokenize this repository?','Which jscpd adapter publishes clone groups into the graph?','Which graph generation field enforces tenant isolation?']}
def main():
    for corpus,items in rows.items():
        functions=json.loads((R/'data'/f'{corpus}-functions.json').read_text()); prefix=S if corpus=='small' else G
        queries=[]
        for i,(kind,text,targets,reason) in enumerate(items,1):
            labels=[]
            for path,symbol in targets:
                matches=[f for f in functions if f['path']==prefix+path and f['symbol']==symbol and not f['overload_stub']]
                assert len(matches)==1,(corpus,path,symbol,matches)
                labels.append(matches[0])
            queries.append({'id':f'{corpus}-{i:02}','class':kind,'query':text,'qrels':labels,'source_justification':reason})
        queries += [{'id':f'{corpus}-N{i}','class':'no_answer','query':text,'qrels':[],'source_justification':'Absent from the approved source inventory; limited closed-corpus judgment, not global absence proof.'} for i,text in enumerate(neg[corpus],1)]
        (R/'data'/f'{corpus}-qrels.json').write_text(json.dumps({'judgment_scope':'Registered function spans only. Other hits remain unjudged. Tests are supporting evidence, never candidates. No answer controls have no calibrated rejection threshold.','queries':queries},indent=2)+'\n')
    config={'schema':'issue162-v1','arms':['exact_symbol','bm25','semantic','rrf'],'bm25':{'k1':1.2,'b':0.75,'tokenizer':'ASCII identifiers and numbers; camel and underscore split; lowercase; retain full identifier too'},'symbol':'exact identifier/FQN token intersection only; no paraphrase expansion','rrf':{'k':60,'weights':[1,1,1]},'top_n':100,'tie_break':'stable chunk id','chunks':{'unit':'AST function implementation including decorators and docstrings','overloads':'exclude stubs in every arm','window_max_encoder_tokens':254,'overlap_lines':2,'long_single_line':'retain source bytes; record encoder truncation','dedup':'function-level first hit for metrics; source-line dedup for context'},'model':{'name':'sentence-transformers/all-MiniLM-L6-v2','revision':'1110a243fdf4706b3f48f1d95db1a4f5529b4d41','sha256':'6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452','max_tokens':256,'pool':'attention-mask mean then L2','dimensions':384,'ort_threads':1},'metrics':{'k':[1,5,10,20],'mrr_k':10,'context_budgets':[2048,8192],'codec':'tiktoken==0.12.0 o200k_base','cold_processes':3,'warm_passes':10},'limits':'Curated registered qrels, not universal recall. No parameter/label changes after ranking.'}
    (R/'data/config.json').write_text(json.dumps(config,indent=2)+'\n')
    hashes={str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((R/'data').glob('*.json'))}
    (R/'data/pre-review-hashes.json').write_text(json.dumps(hashes,indent=2)+'\n'); print(json.dumps(hashes,indent=2))
if __name__=='__main__': main()
