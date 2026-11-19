import json,pathlib,subprocess,time
R=pathlib.Path(__file__).resolve().parent; A=R/'artifacts'
identity=subprocess.check_output(['docker','image','inspect','getzilla-issue170:20261023','--format','{{.Id}}'],text=True).strip()
assert identity=='sha256:e171d370fbeac6c084a9e7af864e86ab6eca1fe2bff1cec99bb59fc6e82f28dc'
args=['docker','build','-f',str(R/'Dockerfile.tests'),'-t','getzilla-issue170-tests:20261023',str(R)]
start=time.monotonic()
with (A/'build-tests.log').open('w') as f:
    p=subprocess.run(['/usr/bin/time','-v','-o',str(A/'build-tests.time'),*args],stdout=f,stderr=subprocess.STDOUT,timeout=240)
(A/'build-tests.json').write_text(json.dumps({'argv':args,'exit_code':p.returncode,'wall_seconds':time.monotonic()-start,'base_image':identity})+'\n')
print('build',p.returncode)
