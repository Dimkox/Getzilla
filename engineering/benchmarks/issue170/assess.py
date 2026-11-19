"""Human-reviewed source-based triage. Cosine is a ranking signal, not proof."""
import csv,json,pathlib
R=pathlib.Path(__file__).resolve().parent; A=R/'artifacts'
functions={f['id']:f for f in json.loads((A/'functions.json').read_text())}
top=json.loads((A/'top20.json').read_text()); rows=[]
for rank,p in enumerate(top,1):
    a,b=functions[p['a']],functions[p['b']]
    category='related_distinct'; tests=[]
    if rank==1:
        category='confirmed_duplicate'
        why='Both property getters have the same signature, docstring and return self.secret_keys[-1]. They read an existing list and have no external effects. This is a tiny compatibility accessor in two distinct public classes; duplication does not imply a useful refactor.'
        tests=['test_signer.py:TestSigner.test_secret_keys (related rotation check; no direct getter assertion in upstream tests)']
    elif a['is_overload'] or b['is_overload']:
        why='These are @overload type declarations with ellipsis bodies, not separate runtime implementations. The signatures distinguish serializer positional/keyword forms or bytes/string serializers, or return_timestamp False/True. Treat a proposed runtime duplicate removal as false positive. Preserve declarations for type checking.'
        category='false_positive'
        tests=['test_serializer.py:TestSerializer.test_serializer','test_timed.py:TestTimestampSigner.test_return_timestamp']
    elif rank==3:
        why='Both return functools.partial with a secret key, but construct URLSafeSerializer and URLSafeTimedSerializer. The timed subclass adds timestamp/expiry behavior and inherits two test contracts. Removing either changes coverage.'
        tests=['test_url_safe.py:TestURLSafeSerializer','test_url_safe.py:TestURLSafeTimedSerializer']
    elif rank==13:
        why='Both assert BadTimeSignature and no date_signed. One creates a signed malformed timestamp with Signer; the other uses a fixed future timestamp byte string. They exercise different parse inputs and must remain distinct regression cases.'
        tests=['test_timed.py:TestTimestampSigner.test_malformed_timestamp','test_timed.py:TestTimestampSigner.test_malformed_future_timestamp']
    elif rank==14:
        why='Both fixtures return partial constructors, but one constructs Signer and the other TimestampSigner. The subclass adds timestamp and max_age contracts; inherited tests reuse the fixture intentionally.'
        tests=['test_signer.py:TestSigner','test_timed.py:TestTimestampSigner']
    elif rank==15:
        why='Both check changed key derivation and round-trip behavior. One injects a custom signer class through signer=Other; the other supplies signer_kwargs. These are distinct configuration paths. A nested class override is a dependency of the first only.'
        tests=['test_serializer.py:TestSerializer.test_signer_cls','test_serializer.py:TestSerializer.test_signer_kwargs']
    elif rank==16:
        why='Both turn unsign success or BadSignature into bool. TimestampSigner.validate adds max_age and passes it to timestamp-aware unsign; Signer.validate has no age contract. Their unsign targets and failure conditions differ. No external effects.'
        tests=['test_signer.py:TestSigner.test_signer','test_timed.py:TestTimestampSigner.test_max_age']
    elif rank==17:
        why='One corrupts a signature and checks recoverable payload under BadSignature. The other signs a malformed payload and checks BadPayload.original_error. Distinct error contracts and dependencies make them related tests, not interchangeable duplicates.'
        tests=['test_serializer.py:TestSerializer.test_bad_signature_exception','test_serializer.py:TestSerializer.test_bad_payload_exception']
    elif rank==18:
        why='Both assert BadTimeSignature with missing date_signed. One omits the timestamp entirely; the other signs an invalid timestamp. Exception message checks distinguish missing and malformed parse branches.'
        tests=['test_timed.py:TestTimestampSigner.test_timestamp_missing','test_timed.py:TestTimestampSigner.test_malformed_timestamp']
    elif rank==20:
        why='signer_factory returns a callable partial(Signer,...); signer calls that fixture and returns a Signer instance. Their result types and fixture roles differ. Replacing one with the other breaks dependency injection.'
        tests=['test_signer.py:TestSigner.test_signer']
    else: raise ValueError('unreviewed pair '+str(rank))
    rows.append({'rank':rank,**p,'classification':category,'reason':why,'source_evidence':[{'id':f['id'],'path':f['path'],'start':f['start'],'end':f['end'],'signature':f['signature'],'returns':f['returns'],'decorators':f['decorators'],'source_sha256':f['sha256'],'calls':f['calls']} for f in (a,b)],'test_references':tests,'validation':'static source review; full upstream suite run separately; no equivalence proof or refactor'})
(A/'candidate-assessment.json').write_text(json.dumps(rows,indent=2)+'\n')
low=list(csv.DictReader((A/'pairs.csv').open()))[-1]
control={'a':low['a'],'b':low['b'],'cosine':float(low['cosine']),'classification':'related_distinct','reason':'base64_decode accepts bytes/text, adds padding, calls urlsafe_b64decode and raises BadData on invalid input. timestamp_to_datetime accepts an integer timestamp and returns an aware UTC datetime through datetime.fromtimestamp. Types, contracts, errors and dependencies differ. Neither performs external writes. This is a low-similarity negative control, not evidence of global retrieval recall.','source_evidence':[functions[low[k]] for k in ('a','b')],'test_references':['test_encoding.py','test_timed.py:TestTimestampSigner.test_return_timestamp']}
(A/'low-control.json').write_text(json.dumps(control,indent=2)+'\n')
lines=['# Top 20 source checks','','Cosine ranks candidates. It is not a duplicate probability. All spans refer to the pinned upstream source. Full snippets and hashes are in functions.json.','']
for row in rows:
    lines += [f"{row['rank']}. **{row['classification']}**; cosine {min(1,row['cosine']):.6f}. `{row['a']}` ↔ `{row['b']}`. {row['reason']}",'']
lines += [f"Low control: cosine {control['cosine']:.6f}. `{control['a']}` ↔ `{control['b']}`. {control['reason']}"]
(R/'candidate-assessment.md').write_text('\n'.join(lines)+'\n')
print({category:sum(r['classification']==category for r in rows) for category in sorted({r['classification'] for r in rows})})
