"""AST inventory and real local ONNX semantic index, no external calls."""
import ast,csv,hashlib,json,pathlib,time
import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer
S=pathlib.Path('/input'); A=pathlib.Path('/work/artifacts')
functions=[]; files=[]
def visit(node,path,text,parents=()):
    for item in ast.iter_child_nodes(node):
        if isinstance(item,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
            ident=parents+(item.name,)
            if isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef)):
                start=min([item.lineno]+[d.lineno for d in item.decorator_list]); end=item.end_lineno
                snippet='\n'.join(text.splitlines()[start-1:end])
                functions.append({'id':f'{path}:{start}:{".".join(ident)}','path':path,'qualified_name':'.'.join(ident),'start':start,'end':end,'signature':ast.unparse(item.args),'returns':None if item.returns is None else ast.unparse(item.returns),'decorators':[ast.unparse(d) for d in item.decorator_list],'is_overload':any(ast.unparse(d) in ('t.overload','typing.overload','overload') for d in item.decorator_list),'source':snippet,'sha256':hashlib.sha256(snippet.encode()).hexdigest(),'calls':sorted({ast.unparse(n.func) for n in ast.walk(item) if isinstance(n,ast.Call)}),'kind':'test' if path.startswith('tests/') else 'production'})
            visit(item,path,text,ident)
        else: visit(item,path,text,parents)
for p in sorted(list((S/'src').rglob('*.py'))+list((S/'tests').rglob('*.py'))):
    text=p.read_text(); path=p.relative_to(S).as_posix()
    files.append({'path':path,'lines':len(text.splitlines()),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
    visit(ast.parse(text),path,text)
(A/'functions.json').write_text(json.dumps(functions,indent=2)+'\n')
(A/'eligible-files.json').write_text(json.dumps(files,indent=2)+'\n')
tok=Tokenizer.from_file('/model/tokenizer.json')
tok.no_padding(); tok.no_truncation()
raw=tok.encode_batch([f['source'] for f in functions]); lengths=[len(x.ids) for x in raw]
tok.enable_truncation(max_length=256); tok.enable_padding()
enc=tok.encode_batch([f['source'] for f in functions])
opts=ort.SessionOptions(); opts.intra_op_num_threads=1; opts.inter_op_num_threads=1
session=ort.InferenceSession('/model/onnx/model.onnx',sess_options=opts,providers=['CPUExecutionProvider'])
vectors=[]; t=time.perf_counter()
for batch_start in range(0,len(enc),16):
    batch=enc[batch_start:batch_start+16]
    inputs={'input_ids':np.array([e.ids for e in batch],dtype=np.int64),'attention_mask':np.array([e.attention_mask for e in batch],dtype=np.int64),'token_type_ids':np.array([e.type_ids for e in batch],dtype=np.int64)}
    hidden=session.run(None,{n.name:inputs[n.name] for n in session.get_inputs()})[0]
    mask=inputs['attention_mask'][:,:,None]; pooled=(hidden*mask).sum(1)/mask.sum(1)
    pooled=pooled/np.linalg.norm(pooled,axis=1,keepdims=True); vectors.append(pooled.astype(np.float32))
v=np.concatenate(vectors); np.save(A/'vectors.npy',v)
assert v.shape==(len(functions),384) and np.isfinite(v).all() and np.allclose(np.linalg.norm(v,axis=1),1,atol=1e-5)
sim=v@v.T; pairs=[]; neighbors=[]
for i,f in enumerate(functions):
    ids=sorted((j for j in range(len(functions)) if j!=i),key=lambda j:(-float(sim[i,j]),functions[j]['id']))[:10]
    neighbors.append({'id':f['id'],'neighbors':[{'id':functions[j]['id'],'cosine':float(sim[i,j])} for j in ids]})
    for j in range(i+1,len(functions)):
        a,b=sorted((f['id'],functions[j]['id']))
        pairs.append({'a':a,'b':b,'cosine':float(sim[i,j]),'same_file':f['path']==functions[j]['path'],'kinds':f['kind']+'/'+functions[j]['kind']})
pairs.sort(key=lambda p:(-p['cosine'],p['a'],p['b']))
(A/'neighbors.json').write_text(json.dumps(neighbors,indent=2)+'\n')
with (A/'pairs.csv').open('w') as out:
    writer=csv.DictWriter(out,fieldnames=list(pairs[0])); writer.writeheader(); writer.writerows(pairs)
(A/'top20.json').write_text(json.dumps(pairs[:20],indent=2)+'\n')
summary={'files':len(files),'lines':sum(f['lines'] for f in files),'functions':len(functions),'count_kind':'AST function declarations, including overloads and nested functions','overload_declarations':sum(f['is_overload'] for f in functions),'non_overload_declarations':sum(not f['is_overload'] for f in functions),'production_functions':sum(f['kind']=='production' for f in functions),'test_functions':sum(f['kind']=='test' for f in functions),'dimensions':384,'max_sequence_length':256,'batch_size':16,'encoder_tokens_before_truncation':sum(lengths),'encoder_tokens_after_truncation':sum(sum(e.attention_mask) for e in enc),'truncated_functions':sum(n>256 for n in lengths),'inference_and_index_wall_seconds':time.perf_counter()-t,'model_inputs':[{'name':n.name,'shape':n.shape,'type':n.type} for n in session.get_inputs()],'model_outputs':[{'name':n.name,'shape':n.shape,'type':n.type} for n in session.get_outputs()],'local_scan_external_llm_calls':0,'local_scan_external_llm_tokens':0,'overall_llm_tokens':None,'ort':ort.__version__,'numpy':np.__version__,'canonical_pairs':len(pairs)}
(A/'index-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary))
