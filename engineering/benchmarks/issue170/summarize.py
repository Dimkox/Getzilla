"""Derive clone pairs/clusters and measured resource summaries from raw evidence."""
import collections,csv,json,pathlib,re
R=pathlib.Path(__file__).resolve().parent; A=R/'artifacts'
clone_summary={}
for threshold in (10,5):
    report=A/f'jscpd-{threshold}/jscpd-report.json'
    if not report.exists():
        clone_summary[str(threshold)]={'status':'missing_raw_report'}; continue
    raw=json.loads(report.read_text()); pairs=[]; adjacency={}
    for d in raw['duplicates']:
        ends=[]
        for label in ('firstFile','secondFile'):
            f=d[label]; ends.append(f"{f['name']}:{f['start']}:{f['end']}")
        a,b=sorted(ends); same=d['firstFile']['name']==d['secondFile']['name']
        pairs.append({'a':a,'b':b,'same_file':same,'lines':d['lines'],'tokens':d['tokens']})
        adjacency.setdefault(a,set()).add(b); adjacency.setdefault(b,set()).add(a)
    seen=set(); clusters=[]
    for node in sorted(adjacency):
        if node in seen: continue
        todo=[node]; group=[]
        while todo:
            n=todo.pop()
            if n in seen: continue
            seen.add(n); group.append(n); todo.extend(adjacency[n]-seen)
        clusters.append(sorted(group))
    clone_summary[str(threshold)]={'status':'observed','raw_pairs':len(pairs),'within_file_pairs':sum(p['same_file'] for p in pairs),'cross_file_pairs':sum(not p['same_file'] for p in pairs),'connected_clusters':len(clusters),'cluster_identity':'raw exact file/start/end spans; overlapping but unequal spans are distinct nodes; reversed raw spans retained, not validated source ranges','reversed_raw_spans':sum(d[f]['end']<d[f]['start'] for d in raw['duplicates'] for f in ('firstFile','secondFile')),'min_tokens':50,'parser':'python','mode':'mild','pairs':pairs,'clusters':clusters,'statistics':raw['statistics']}
(A/'clone-summary.json').write_text(json.dumps(clone_summary,indent=2)+'\n')
metrics=json.loads((A/'metrics.json').read_text())
for m in metrics:
    text=(A/f"{m['stage']}.time").read_text()
    def number(label):
        match=re.search(re.escape(label)+r':\s*([0-9.]+)',text)
        return None if not match else float(match.group(1))
    m.update(user_seconds=number('User time (seconds)'),system_seconds=number('System time (seconds)'),peak_rss_kib=number('Maximum resident set size (kbytes)'))
(A/'metrics-derived.json').write_text(json.dumps(metrics,indent=2)+'\n')
sizes={}
for name in ['original','core','model','downloads','work','artifacts']:
    files=[p for p in (R/name).rglob('*') if p.is_file() and not p.is_symlink()]
    sizes[name]={'files':len(files),'logical_bytes':sum(p.stat().st_size for p in files)}
(A/'disk-sizes.json').write_text(json.dumps(sizes,indent=2)+'\n')
graph=json.loads((A/'graph-export.stdout').read_text())['export']
functions=json.loads((A/'functions.json').read_text())
groups=collections.defaultdict(list)
for f in functions: groups[(f['path'],f['qualified_name'])].append(f)
collapsed=[]
for symbol in graph['symbols']:
    declarations=groups.get((symbol['path'],symbol['qualname']),[])
    if len(declarations)>1:
        collapsed.append({'graph_symbol':symbol,'ast_declarations':[{'start':f['start'],'end':f['end'],'is_overload':f['is_overload']} for f in declarations]})
gs={'symbol_kinds':dict(collections.Counter(s['kind'] for s in graph['symbols'])),'parsed_python_files':15,'ast_eligible_python_files':14,'extra_python_file':'docs/conf.py','unresolved_calls':graph['coverage']['unresolved_calls'],'unresolved_imports':graph['coverage']['unresolved_imports'],'overloaded_identity_groups':collapsed,'coverage_complete':graph['coverage']['complete'],'symbols':graph['symbols']}
(A/'graph-summary.json').write_text(json.dumps(gs,indent=2)+'\n')
print('graph',gs['symbol_kinds'],'collapsed',len(collapsed))
print(json.dumps({'clones':{k:{x:v.get(x) for x in ['raw_pairs','within_file_pairs','cross_file_pairs','connected_clusters']} for k,v in clone_summary.items()},'stages':metrics},indent=2))
