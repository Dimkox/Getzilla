"""Offline fixed-arm retrieval experiment. Requires an independently reviewed seal."""
import collections,hashlib,json,math,os,pathlib,re,resource,statistics,sys,time
import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer
import tiktoken
from trusted_read import read_hit
R=pathlib.Path('/work'); OUT=R/'results'; OUT.mkdir(exist_ok=True)
def sha(data):return hashlib.sha256(data).hexdigest()
def write(path,obj):path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
def tokens(text):
    out=[]
    for full in re.findall(r'[A-Za-z_][A-Za-z_0-9]*|[0-9]+',text):
        pieces=re.sub(r'([a-z0-9])([A-Z])',r'\1 \2',full).replace('_',' ').lower().split()
        out.append(full.lower());out.extend(p for p in pieces if p!=full.lower())
    return out
def pct(xs,p):return float(np.percentile(xs,p))
class Encoder:
    def __init__(self):
        self.tokenizer=Tokenizer.from_file('/model/tokenizer.json');self.tokenizer.no_padding();self.tokenizer.no_truncation()
        options=ort.SessionOptions();options.intra_op_num_threads=1;options.inter_op_num_threads=1
        self.session=ort.InferenceSession('/model/onnx/model.onnx',sess_options=options,providers=['CPUExecutionProvider'])
        self.truncations=[]
    def count(self,text):return len(self.tokenizer.encode(text).ids)
    def encode(self,texts):
        vectors=[]
        for offset in range(0,len(texts),32):
            enc=self.tokenizer.encode_batch(texts[offset:offset+32]); ids=[e.ids[:256] for e in enc]
            # Preserve final SEP after bounded truncation; raw length was measured first.
            for e,row in zip(enc,ids):
                if len(e.ids)>256:row[-1]=self.tokenizer.token_to_id('[SEP]')
            n=max(map(len,ids));inputs=np.zeros((len(ids),n),dtype=np.int64);mask=np.zeros_like(inputs)
            for i,row in enumerate(ids):inputs[i,:len(row)]=row;mask[i,:len(row)]=1
            args={'input_ids':inputs,'attention_mask':mask,'token_type_ids':np.zeros_like(inputs)}
            result=self.session.run(None,{x.name:args[x.name] for x in self.session.get_inputs()})[0]
            pooled=(result*mask[:,:,None]).sum(axis=1)/mask.sum(axis=1)[:,None]
            pooled=pooled/np.maximum(np.linalg.norm(pooled,axis=1,keepdims=True),1e-12)
            vectors.extend(pooled.astype(np.float32))
        return np.array(vectors,dtype=np.float32)
def chunks_for(corpus,encoder):
    functions=json.loads((R/'data'/f'{corpus}-functions.json').read_text());chunks=[]
    for f in functions:
        if f['overload_stub']:continue
        raw=(pathlib.Path('/sources')/corpus/f['path']).read_bytes();lines=raw.splitlines(keepends=True)
        start=f['start']
        while start<=f['end']:
            end=start
            while end<f['end'] and encoder.count(b''.join(lines[start-1:end+1]).decode())<=254:end+=1
            data=b''.join(lines[start-1:end]);text=data.decode();count=encoder.count(text)
            chunks.append({**f,'function_id':f['id'],'id':f'{f["id"]}@{start}-{end}','start':start,'end':end,'sha256':sha(data),'text':text,'encoder_tokens':count,'encoder_truncated':count>256,'tenant':'benchmark','repository':corpus,'kind':'function','schema':'issue162-v1'})
            if end==f['end']:break
            start=max(start+1,end-1)
    return sorted(chunks,key=lambda x:x['id'])
class Search:
    def __init__(self,chunks,vectors):
        self.chunks=chunks;self.vectors=vectors;self.counts=[collections.Counter(tokens(c['text'])) for c in chunks]
        self.lengths=np.array([sum(c.values()) for c in self.counts]);self.avg=float(self.lengths.mean())
        df=collections.Counter(t for row in self.counts for t in row);self.idf={t:math.log(1+(len(chunks)-n+.5)/(n+.5)) for t,n in df.items()}
        self.symbols=[set(re.findall(r'[A-Za-z_][A-Za-z_0-9]*',c['symbol']))|{c['symbol']} for c in chunks]
    def ranked(self,scores,positive=False):
        return [(i,float(scores[i])) for i in sorted(range(len(scores)),key=lambda i:(-float(scores[i]),self.chunks[i]['id'])) if not positive or scores[i]>0][:100]
    def query(self,text,vector):
        started=time.perf_counter();exact=set(re.findall(r'[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*',text))
        # Exact FQN tokens plus identifier tokens, with case preserved.
        exact |= {part for item in exact for part in item.split('.')}
        symbol=self.ranked([len(exact&s) for s in self.symbols],True)
        symbol_ms=(time.perf_counter()-started)*1000;started=time.perf_counter()
        scores=np.zeros(len(self.chunks))
        for term in tokens(text):
            tf=np.array([row.get(term,0) for row in self.counts]);scores+=self.idf.get(term,0)*tf*2.2/(tf+1.2*(.25+.75*self.lengths/self.avg))
        bm=self.ranked(scores,True);bm_ms=(time.perf_counter()-started)*1000;started=time.perf_counter()
        semantic=self.ranked(self.vectors@vector);sem_ms=(time.perf_counter()-started)*1000;started=time.perf_counter()
        fused=collections.defaultdict(float)
        for ranking in (symbol,bm,semantic):
            for rank,(i,_) in enumerate(ranking,1):fused[i]+=1/(60+rank)
        rrf=sorted(fused.items(),key=lambda pair:(-pair[1],self.chunks[pair[0]]['id']))[:100]
        return {'exact_symbol':symbol,'bm25':bm,'semantic':semantic,'rrf':rrf},{'exact_symbol':symbol_ms,'bm25':bm_ms,'semantic':sem_ms,'rrf_fusion':(time.perf_counter()-started)*1000}
def dedup(ranking,chunks,key):
    seen=set();out=[]
    for i,score in ranking:
        item=chunks[i][key]
        if item not in seen:seen.add(item);out.append((i,score))
    return out
def evaluate(query,ranking,chunks,codec,budget):
    relevant={f['id'] for f in query['qrels']};files={f['path'] for f in query['qrels']}
    function_rank=dedup(ranking,chunks,'function_id');file_rank=dedup(ranking,chunks,'path')
    metrics={}
    for k in (1,5,10,20):
        metrics[f'function_recall@{k}']=len(relevant&{chunks[i]['function_id'] for i,_ in function_rank[:k]})/len(relevant)
        metrics[f'file_recall@{k}']=len(files&{chunks[i]['path'] for i,_ in file_rank[:k]})/len(files)
    metrics['mrr@10']=next((1/r for r,(i,_) in enumerate(function_rank[:10],1) if chunks[i]['function_id'] in relevant),0)
    used=0;included=[];seen_lines=set();context=[]
    for i,_ in ranking:
        c=chunks[i];lines=c['text'].splitlines(keepends=True);fresh=[(n,line) for n,line in enumerate(lines,c['start']) if (c['path'],n) not in seen_lines]
        if not fresh:continue
        # Citation states the original exact range; included source line numbers disclose overlap removal.
        header=f"[{c['repository']} {c['path']}:{c['start']}-{c['end']} sha256={c['file_sha256']} source-lines={','.join(str(n) for n,_ in fresh)}]\n"
        piece=header+''.join(line for _,line in fresh)+'\n---\n'
        prospective=''.join(context)+piece;count=len(codec.encode(prospective))
        if count>budget:continue
        used=count;context.append(piece);included.append(c['function_id']);seen_lines.update((c['path'],n) for n,_ in fresh)
    metrics[f'budget_{budget}_recall']=len(relevant&set(included))/len(relevant)
    metrics[f'budget_{budget}_tokens']=used
    return metrics
def check_seal():
    seal=json.loads((R/'data/seal.json').read_text())
    assert seal['independent_qrel_review']=='pass'
    for name,digest in seal['hashes'].items():assert sha((R/name).read_bytes())==digest,name
    return seal
def run(corpus):
    seal=check_seal();cold_start=time.perf_counter();encoder=Encoder();load_seconds=time.perf_counter()-cold_start
    codec=tiktoken.get_encoding('o200k_base');start=time.perf_counter();chunks=chunks_for(corpus,encoder)
    vectors=encoder.encode([c['text'] for c in chunks]);search=Search(chunks,vectors);index_seconds=time.perf_counter()-start
    np.save(OUT/f'{corpus}-vectors.npy',vectors);write(OUT/f'{corpus}-chunks.json',chunks)
    queries=json.loads((R/'data'/f'{corpus}-qrels.json').read_text())['queries'];results=[];timings=[]
    for iteration in range(10):
        for query in queries:
            start=time.perf_counter();vector=encoder.encode([query['query']])[0];embed_ms=(time.perf_counter()-start)*1000
            rankings,latency=search.query(query['query'],vector);total=(time.perf_counter()-start)*1000
            timings.append({'pass':iteration,'query':query['id'],'query_embedding_ms':embed_ms,'all_arms_end_to_end_ms':total,**latency,'semantic_end_to_end_ms':embed_ms+latency['semantic'],'rrf_end_to_end_ms':embed_ms+sum(latency.values())})
            if iteration:continue
            for arm,ranking in rankings.items():
                result={'query':query['id'],'class':query['class'],'arm':arm,'rankings':[{'chunk_id':chunks[i]['id'],'function_id':chunks[i]['function_id'],'path':chunks[i]['path'],'score':score,'rank':rank,'start':chunks[i]['start'],'end':chunks[i]['end'],'file_sha256':chunks[i]['file_sha256'],'chunk_sha256':chunks[i]['sha256']} for rank,(i,score) in enumerate(ranking,1)]}
                if query['qrels']:
                    result['metrics']={**evaluate(query,ranking,chunks,codec,2048),**evaluate(query,ranking,chunks,codec,8192)}
                else:result['no_answer']={'returned':len(ranking),'top_score':ranking[0][1] if ranking else None,'threshold':'none; returned candidates do not establish answerability'}
                results.append(result)
    allowed={c['path'] for c in chunks};citations=0
    for c in chunks:
        assert read_hit(pathlib.Path('/sources')/corpus,c,'benchmark',corpus,allowed).decode()==c['text'];citations+=1
    # Independent copied-byte view: no Git metadata or ancestor exists at either mount.
    other=[]
    for c in chunks:
        assert read_hit(pathlib.Path('/gitless')/corpus,c,'benchmark',corpus,allowed).decode()==c['text']
        other.append(c['sha256'])
    parity_vectors=encoder.encode([read_hit(pathlib.Path('/gitless')/corpus,c,'benchmark',corpus,allowed).decode() for c in chunks]);parity_search=Search(chunks,parity_vectors)
    parity=True
    for query in queries:
        v=encoder.encode([query['query']])[0]
        a,_=search.query(query['query'],v);b,_=parity_search.query(query['query'],v)
        parity &= a==b
    assert parity
    write(OUT/f'{corpus}-results.json',results);write(OUT/f'{corpus}-timings.json',timings)
    metrics={'corpus':corpus,'cold_model_load_seconds':load_seconds,'index_build_seconds':index_seconds,'functions':len({c['function_id'] for c in chunks}),'chunks':len(chunks),'encoder_truncated_chunks':sum(c['encoder_truncated'] for c in chunks),'encoder_tokens_untruncated':sum(c['encoder_tokens'] for c in chunks),'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'vectors_bytes':vectors.nbytes,'citations_checked':citations,'gitless':{'bytes_and_ranges_equal':True,'rankings_equal':parity,'git_dependency':False,'note':'Git object input provenance verified by pinned blob materialization; both retrieval views contain plain copied files.'},'latency_summary':{key:{'median':statistics.median(t[key] for t in timings),'p95':pct([t[key] for t in timings],95)} for key in timings[0] if key not in ('pass','query')},'seal':seal,'external_scan_index_llm_calls':0,'external_scan_index_llm_tokens':0,'orchestration_usage':None}
    write(OUT/f'{corpus}-metrics.json',metrics);print(json.dumps(metrics),flush=True)
if __name__=='__main__':
    if sys.argv[1]=='cold':
        start=time.perf_counter();e=Encoder();print(json.dumps({'cold_model_load_seconds':time.perf_counter()-start,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}));sys.exit()
    run(sys.argv[1])
