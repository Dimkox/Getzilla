"""Capture only process/container capacity, fixed asset bytes and tool identity."""
import json,os,pathlib,platform,resource
paths=['/proc/self/cgroup','/sys/fs/cgroup/cpu.max','/sys/fs/cgroup/cpuset.cpus.effective','/sys/fs/cgroup/memory.max']
data={'platform':platform.platform(),'python':platform.python_version(),'affinity':sorted(os.sched_getaffinity(0)),'cpu_count':os.cpu_count(),'bounds':{p:pathlib.Path(p).read_text() if pathlib.Path(p).exists() else None for p in paths},'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
print(json.dumps(data,indent=2))
