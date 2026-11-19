import json,os,pathlib,platform
A=pathlib.Path('/work/artifacts')
record={'python':platform.python_version(),'platform':platform.platform(),'affinity':sorted(os.sched_getaffinity(0)),'logical_cpu_count':os.cpu_count()}
for name in ['cpu.max','cpuset.cpus.effective','memory.max']:
    p=pathlib.Path('/sys/fs/cgroup')/name
    record[name]=p.read_text().strip() if p.exists() else None
(A/'container-capacity.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
