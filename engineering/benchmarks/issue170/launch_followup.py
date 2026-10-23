import json,pathlib,subprocess,time
R=pathlib.Path(__file__).resolve().parent; A=R/'artifacts'
args=json.loads((A/'launch-command.json').read_text())
args[args.index('getzilla-issue170:20261023')]='getzilla-issue170-tests:20261023'
args[-1]='/scripts/followup.py'
(A/'followup-command.json').write_text(json.dumps(args,indent=2)+'\n')
start=time.monotonic()
with (A/'followup.log').open('w') as f:
    p=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=600)
(A/'followup-result.json').write_text(json.dumps({'exit_code':p.returncode,'wall_seconds':time.monotonic()-start})+'\n')
print('followup',p.returncode)
