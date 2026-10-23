"""Delete only this benchmark's owned resources after review. Never prune shared caches."""
import argparse,json,os,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parent
parser=argparse.ArgumentParser(); parser.add_argument('--execute',action='store_true'); args=parser.parse_args()
assert R.name=='issue170-20261023T2152' and R.parent.name=='scratch'
assert R.stat().st_uid==os.getuid() and R.stat().st_mode&0o777==0o700
assert (R/'publication/SHA256SUMS.json').is_file()
for name,digest in json.loads((R/'publication/SHA256SUMS.json').read_text()).items():
    import hashlib
    assert hashlib.sha256((R/'publication'/name).read_bytes()).hexdigest()==digest,name
targets=['work','model','core','downloads','original']
for name in targets:
    p=R/name
    assert not p.is_symlink() and p.resolve().parent==R
    if p.exists(): assert p.stat().st_uid==os.getuid()
images=json.loads((R/'artifacts/image-identities.json').read_text())
for tag,record in images.items():
    actual=subprocess.check_output(['docker','image','inspect',tag,'--format','{{.Id}}'],text=True).strip()
    assert actual==record.split()[0]
print(json.dumps({'validated_directories':targets,'validated_image_tags':list(images),'execute':args.execute}))
if args.execute:
    for name in targets:
        p=R/name
        if p.exists(): shutil.rmtree(p)
    for tag in reversed(list(images)):
        subprocess.run(['docker','image','rm',tag],check=True)
    (R/'cleanup-result.json').write_text(json.dumps({'owned_directories_removed':targets,'owned_image_tags_removed':list(images),'shared_cache_pruned':False})+'\n')
