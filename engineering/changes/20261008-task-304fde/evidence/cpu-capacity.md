# CPU capacity snapshot (security follow-up writer)
timestamp: 2026-10-08T18:46:34+03:00
lscpu: CPU(s): 8;On-line CPU(s) list: 0-7;Thread(s) per core: 1;Core(s) per socket: 8;Socket(s): 1
nproc --all: 8
nproc: 8
taskset: pid 3989191's current affinity list: 0-7
cgroup: 0::/agent; cpuset.cpus.effective=0-7; cpu.max=absent
affinity-widening probe: not needed (affinity == cpuset == online)
load: 6.62 6.92 5.84 9/1202 3989224
capacity: 8 logical CPUs shared with 3 other workers; budget GETZILLA_TEST_WORKERS=2
