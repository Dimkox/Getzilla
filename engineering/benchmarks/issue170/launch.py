"""Host entry point. Network is disabled for all project analysis."""
import hashlib,json,pathlib,subprocess,time
R=pathlib.Path(__file__).resolve().parent
(R/'work').mkdir(exist_ok=True)
for name in ['container.log','container-result.json','launch-command.json']:
    p=R/'artifacts'/name
    if p.exists(): p.rename(p.with_name('attempt1-'+name))
args=['docker','run','--rm','--name','getzilla-issue170-20261023','--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--cpuset-cpus','0-19','--cpus','20','--memory','4g','--pids-limit','256','--user',f'{__import__("os").getuid()}:{__import__("os").getgid()}','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=512m','-v',f'{R}/original:/input:ro','-v',f'{R}/core:/core:ro','-v',f'{R}/model:/model:ro','-v',f'{R}:/scripts:ro','-v',f'{R}/work:/work:rw','-v',f'{R}/artifacts:/work/artifacts:rw','getzilla-issue170:20261023','python','/scripts/run.py']
(R/'artifacts/launch-command.json').write_text(json.dumps(args,indent=2)+'\n')
start=time.monotonic()
with (R/'artifacts/container.log').open('w') as f:
    p=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
(R/'artifacts/container-result.json').write_text(json.dumps({'exit_code':p.returncode,'wall_seconds':time.monotonic()-start})+'\n')
print('container exit',p.returncode)
