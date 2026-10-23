"""Fetch fixed model assets only; never upload source."""
import concurrent.futures,hashlib,json,pathlib,urllib.request
R=pathlib.Path(__file__).resolve().parent
REV='1110a243fdf4706b3f48f1d95db1a4f5529b4d41'
def get(name):
    url=f'https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/{REV}/{name}'
    p=R/'model'/name;p.parent.mkdir(parents=True,exist_ok=True)
    with urllib.request.urlopen(url,timeout=180) as response,p.open('wb') as f:
        while b:=response.read(1024*1024): f.write(b)
    return {'path':name,'url':url,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
if __name__=='__main__':
    names=['onnx/model.onnx','tokenizer.json','tokenizer_config.json','config.json','special_tokens_map.json','vocab.txt','sentence_bert_config.json','1_Pooling/config.json','README.md']
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: rows=list(pool.map(get,names))
    assert rows[0]['sha256']=='6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452'
    assert rows[0]['bytes']==90405214
    (R/'data/model-pins.json').write_text(json.dumps(rows,indent=2)+'\n')
    print('model verified; no inference performed')
