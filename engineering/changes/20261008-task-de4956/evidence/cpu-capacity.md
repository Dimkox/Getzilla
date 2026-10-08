# CPU capacity snapshot (security writer, wt-sec)
timestamp: 2026-10-08T17:52:04+03:00
lscpu: CPU(s)=8, On-line 0-7, Thread(s) per core=1, Core(s) per socket=8, Socket(s)=1, Intel Xeon (KVM guest)
nproc --all: 8
nproc: 8
taskset -pc $$: current affinity list 0-7
cgroup: 0::/agent (v2); cpuset.cpus.effective=0-7; cpu.max absent (no finite quota found in /sys/fs/cgroup)
affinity-widening probe: not needed (affinity == cpuset == online CPUs)
load average at start: 3.98 4.53 3.81 (host shared with other workers; one runs verify suites with 4 workers)
effective capacity: 8 logical CPUs, shared; this writer's budget = 2 test workers (GETZILLA_TEST_WORKERS=2)
