"""Freeze an evidence-only publication bundle; retain owned tools until review."""
import collections,hashlib,json,os,pathlib,shutil,subprocess,tarfile
R=pathlib.Path(__file__).resolve().parent; A=R/'artifacts'
def load(name): return json.loads((A/name).read_text())
image={}
for tag in ['getzilla-issue170:20261023','getzilla-issue170-tests:20261023']:
    image[tag]=subprocess.check_output(['docker','image','inspect',tag,'--format','{{.Id}} {{.Size}}'],text=True).strip()
(A/'image-identities.json').write_text(json.dumps(image,indent=2)+'\n')
subprocess.run(['git','-C',str(R/'work/candidate'),'bundle','create',str(A/'candidate.bundle'),'--all'],check=True)
verify=R/'work/candidate/.getzilla/runtime/evidence/verification.json'
if verify.exists(): shutil.copyfile(verify,A/'candidate-verification-runtime.json')
metrics=load('metrics-derived.json'); index=load('index-summary.json'); clones=load('clone-summary.json'); graph=load('graph-summary.json'); added=load('adoption-files.json'); payload=load('payload-validation.json')
for m in metrics:
    m['retained_stage_log_bytes']=sum(p.stat().st_size for p in A.glob(m['stage']+'.*') if p.is_file())
(A/'metrics-derived.json').write_text(json.dumps(metrics,indent=2)+'\n')
setup={'source_download_wall_seconds':None,'source_download_peak_rss_kib':None,'initial_build_wall_seconds':None,'initial_build_peak_rss_kib':None,'initial_build_observed_steps_seconds':{'apt':114.6,'pip':65.4,'npm':18.5,'export_and_unpack':79.9},'initial_build_measurement':'BuildKit observed stage durations copied from terminal; no complete build log or aggregate RSS captured','lifecycle':'Native SubagentStart child ID and generation were not exposed; no lifecycle event identity invented','initial_extension_build_failure':'FROM local name@sha256 attempted Docker Hub resolution and failed insufficient_scope; fixed to local tag after asserting exact local image ID','preflight':{'experiment_mode':oct(R.stat().st_mode&0o777),'free_disk_before_preparation':'276 GiB observed with df -h','network':'GitHub source and Hugging Face immutable model downloads succeeded; registry, apt, pip, npm preparation succeeded; analysis network=none','scope':'all inputs and outputs below experiment root; no product edits; no source upload'}}
(A/'preflight-and-setup.json').write_text(json.dumps(setup,indent=2)+'\n')
rows=[]
for m in metrics:
    if m['stage'] in ('core-plan','core-apply','graph-build','graph-export','jscpd-10','jscpd-5','index','index-corrected','upstream-tests','upstream-tests-final','candidate-verify','candidate-verify-final'):
        rows.append(f"| {m['stage']} | {m['exit_code']} | {m['wall_seconds']:.3f} | {m['user_seconds']+m['system_seconds']:.2f} | {m['peak_rss_kib']/1024:.1f} | {m['retained_stage_log_bytes']} |")
skips=[c['name']+': '+c['summary'] for c in load('candidate-verify-final.stdout')['checks'] if c['status']=='skip']
raw_extra=sorted(set(added['added'])-{e['path'] for e in payload['entries']})
report=f'''# Issue 170: real isolated benchmark

The benchmark succeeded on itsdangerous 2.2.0. Zero-Git adoption, graph export, both clone scans and a true local ONNX index ran. The upstream suite passed **297 tests**. The adopted candidate fast verifier passed after installing a missing test dependency. No refactor or Getzilla product change was made.

Inputs: upstream commit `096c8d42545d3b68ea21a4f890fb2b2d8979c0bd`; Getzilla **2.3.1**, commit `8352756ccddbb7b9f13da2da689ef633d968e30f`; MiniLM model revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`. See `artifacts/input-pins.json` for URLs, sizes and SHA-256 hashes. The upstream BSD-3-Clause license is preserved in the source archive. The model repository declares Apache-2.0. No remote model code was loaded.

The 60-file original remained unchanged. The eligible scope has **14 Python files, 1,681 physical lines and 116 AST function declarations**: 62 in production code and 54 in tests. Nine declarations are `@overload` signatures. There are 107 non-overload declarations, including nested functions. These counts do not include installed Core code. The empty test package file is eligible but has no tokens. jscpd reports 13 nonempty sources and 1,668 lexer lines; that is a different line convention.

Core plan and apply exited 0. Adoption created two local commits, with no remote. The original baseline is `c51f4f1f95afb2408cff5c23ac8fb53e4151869b`. The managed commit is `81eadf1d28792d79e49c0c538080ba5b9c8799e9`. All **710 expected payload files** match their pinned installer bytes and executable modes. The only additional non-source file outside that payload is `{', '.join(raw_extra)}`. The adopted tree has 771 regular non-Git files before verification. The installer returned `integrity_status=verified` and `project_health_status=not_run`. It installed the actual full managed payload; this was not a minimal-component install.

The separate candidate fast verifier passed with `--no-record`. It wrote its runtime JSON in the disposable candidate. It had no active route and no comparison base. It is **not a PR gate or merge receipt**. The first run failed because `freezegun` was missing. The owned tool image then added upstream-pinned freezegun 1.4.0, python-dateutil 2.9.0.post0 and six 1.16.0. Both the original-source suite and the candidate verifier passed on retry. Candidate test imports used candidate/src on retry. The original first-run failures remain in the evidence.

Getzilla graph parsed 15 Python files, including docs/conf.py outside the eligible scan scope. It exported **136 symbols: 107 functions and 29 classes**, plus 379 calls and 132 imports. Its whole-source coverage is incomplete: 250 calls and 73 imports remain unresolved, and non-Python files are not covered. Three overloaded identities collapse to one graph symbol each. For example, TimestampSigner.unsign points at its first overload span, not its runtime body. The AST supplement keeps every declaration with file, range, signature, decorators and source hash. See graph-summary.json for exact collapsed groups.

| Text scan | Raw clone pairs | Within file | Across files | Raw span clusters | Raw line % | Raw token % |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| minLines 10 | {clones['10']['raw_pairs']} | {clones['10']['within_file_pairs']} | 0 | {clones['10']['connected_clusters']} | 2.52 | 4.34 |
| minLines 5 | {clones['5']['raw_pairs']} | {clones['5']['within_file_pairs']} | 0 | {clones['5']['connected_clusters']} | 3.06 | 5.37 |

Both runs used jscpd 4.0.5, Python lexer, mild mode and minTokens 50. Both scanned only original src/tests. Zero cross-file pairs is an observed result. The raw reports contain reversed end ranges ({clones['10']['reversed_raw_spans']} at minLines 10; {clones['5']['reversed_raw_spans']} at minLines 5) and per-pair tokens=0. The reports remain unchanged. Clusters connect exact raw file/start/end labels, including malformed ones; they are **not validated semantic duplicate groups**. The minLines 10 fragments repeat serializer overload signature scaffolding. Do not use the raw reversed ranges for edits.

The local index uses ONNX Runtime 1.23.2, tokenizers 0.22.1 and NumPy 2.2.6. It uses CPUExecutionProvider, one intra-op thread, one inter-op thread, batch size 16, max sequence 256, attention-mask mean pooling and L2 normalization. All 116 vectors are finite and have 384 dimensions and unit norm within tolerance. There are 6,670 canonical non-self pairs and ten deterministic cosine neighbors per declaration. Raw float32 cosine can exceed 1 by rounding (maximum observed 1.000000119); display values round to six decimals. A cosine is not a duplicate probability.

Correct token counts: **{index['encoder_tokens_before_truncation']:,}** before truncation; **{index['encoder_tokens_after_truncation']:,}** after truncation; **{index['truncated_functions']}** truncated declarations. Counts include tokenizer special tokens and exclude padding. The tokenizer JSON had pre-enabled padding/truncation. The initial measurement therefore miscounted tokens and falsely showed zero truncation. The corrected run first disables those settings. Initial index files are retained as `initial-*` and are superseded. Corrected vectors reproduce the initial ranking.

Source checks of the top 20 found **one confirmed identical getter pair, 11 overload false positives and eight related but distinct pairs**. The getter pair returns the newest secret key in two public classes. It has no external effect. Its tiny size does not justify a refactor. Distinct timestamp validation, fixture roles and error contracts explain the other runtime candidates. The low-score control pairs base64 decoding with UTC timestamp conversion (cosine 0.036764); their types, dependencies and error contracts differ. `candidate-assessment.md` and its JSON give all 20 decisions, source ranges, signatures, calls and related tests. These are bounded source reviews, not a proof of equivalence or global recall.

Local scan/index external LLM calls and tokens are **0**. Local encoder token counts are above. Overall orchestration and candidate-review LLM token use is **null**, because it was not measured.

| Stage | Exit | Wall s | CPU s | Peak RSS MiB | Retained stage log bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(rows)}

Wall time uses a monotonic clock. CPU time is GNU time user+system. Peak RSS is the stage process accounting reported by GNU time; it is not whole-host or image-build peak memory. Independent graph, clone scans, index and original tests overlapped. Do not add their wall times to estimate elapsed time. Full metrics and exact argv are in metrics-derived.json and raw *.time files. Disk sizes are retained logical file bytes in disk-sizes.json. Per-stage log bytes exclude shared index/candidate products. No peak temporary disk figure was measured.

Preparation had 276 GiB free space and a mode-0700 experiment root. Immutable source/model downloads and registry/package downloads succeeded. BuildKit showed apt 114.6 s, pip 65.4 s, npm 18.5 s and image export/unpack 79.9 s. Overall initial setup wall time and peak RSS were not captured and remain null. The test-dependency build has separate raw logs and GNU time metrics. Image identities, all wheel hashes, installed package versions and npm lock integrity hashes are retained. The base Python image is pinned by digest in Dockerfile.

The host startup measured 26 effective CPUs. The Docker daemon rejected quota 24 with exit 125 because it reported 22 available CPUs. That failure is retained. The successful container independently reported affinity/cpuset 0-19, cpu.max=2000000/100000 (20 CPUs) and memory.max=4 GiB. The container had no network, dropped all capabilities, had no-new-privileges, and ran as the host user's numeric UID. Original source, pinned Core and model mounts were read-only. Only owned work/artifact paths were writable. No host home, credential, Docker socket or production mount was given to project execution.

For issue 162: retain source-span provenance; distinguish overload declarations from implementations before ranking; expose incomplete graph coverage; validate clone tool ranges before consuming them; log model/tokenizer/tool revisions and real truncation; require contract/test review before any refactor. This small benchmark does not establish a universal similarity threshold, precision or recall.

Reproduce in a fresh owned experiment directory: run prepare.py; run test_inputs.py; build Dockerfile with tag getzilla-issue170:20261023; run launch.py; build Dockerfile.tests (assert the local base identity, or update that assertion only for a deliberately rebuilt tool image); run launch_followup.py; run summarize.py and assess.py. Dependencies are in the Dockerfiles, the exact resolved wheel hashes and npm package-lock are in artifacts. Downloads require network; all project stages run with network=none. The first setup intentionally lacks freezegun and records its failure before the declared dependency repair. Do not rerun adoption against its existing target. The candidate Git bundle preserves both actual commits for inspection.

No product rollout occurred. Rollback is deletion of experiment-owned targets and caches only. Tools, model and candidate are retained until independent review finishes. The cleanup script validates ownership and exact paths, then deletes only those resources. It never prunes shared Docker or package caches. Docker build-cache layers may remain in the shared daemon because shared pruning is out of scope. The publication bundle retains source/license, reproducible scripts, raw evidence, index and candidate bundle. The coordinator handles the unmerged evidence branch and issue links. No merge, CI integration or external source upload is part of this run.
'''
(R/'report.md').write_text(report)
(R/'decisions.md').write_text('Use a container mount view for Zero-Git input below a Git checkout. It preserved the installer Git-ancestor check and allowed real adoption without changing product code. Keep overload declarations in raw inventory, but classify them before interpreting duplicate rankings.\n')
(R/'mistakes.md').write_text('The tokenizer JSON carries active padding/truncation settings; counting raw ids without clearing them produced false token totals. Disable both before raw length measurement, then apply the requested 256-token policy. Initial tool preparation omitted declared freezegun; read the upstream test requirements before the first test run.\n')
P=R/'publication'; P.mkdir(exist_ok=True)
for name in ['report.md','candidate-assessment.md','decisions.md','mistakes.md','prepare.py','test_inputs.py','Dockerfile','Dockerfile.tests','.dockerignore','build_tests.py','launch.py','launch_followup.py','run.py','followup.py','analyze.py','observe.py','summarize.py','assess.py','finalize.py','cleanup.py']:
    shutil.copyfile(R/name,P/name)
shutil.copytree(A,P/'artifacts',dirs_exist_ok=True)
with tarfile.open(P/'upstream-source.tar.gz','w:gz') as t: t.add(R/'original',arcname='itsdangerous-2.2.0')
manifest={p.relative_to(P).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(P.rglob('*')) if p.is_file() and p.name!='SHA256SUMS.json'}
(P/'SHA256SUMS.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'publication_files':len(manifest),'publication_bytes':sum(p.stat().st_size for p in P.rglob('*') if p.is_file()),'manifest_sha256':hashlib.sha256((P/'SHA256SUMS.json').read_bytes()).hexdigest()}))
