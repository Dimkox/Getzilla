# CPU capacity snapshot (AGENTS.md step 0)

```text
CPU capacity snapshot (Getzilla AGENTS.md step 0), 2026-10-08 17:38 MSK, box
lscpu: 8 CPUs, 8 cores/socket, 1 thread/core, 1 socket (Intel Xeon)
nproc --all: 8 ; nproc: 8 ; taskset -pc $$: 0-7
cgroup: 0::/agent ; /sys/fs/cgroup/agent/cpu.max = "max 100000" (no quota) ; cpuset.cpus.effective = 0-7 (agent and root)
widening probe: not needed (affinity == cpuset)
verified effective capacity: 8 ; shared with a read-only audit worker -> my budget 6 workers
load average at snapshot: 3.27 2.46 2.15
17:41 rebalance: budget lowered to 4 workers (2 more reviewers); trust-ci verify stopped, gz-fix(2)+gz-queue(2) continue
## 18:12 MSK rebalance: main baseline done; integration verify 1 worker + per-branch queue 2 workers = 3
## 18:28 MSK: main 07b461c verify alone, 3 workers
2026-10-08 17:57 rebalance: budget 3 workers (more agents share the box)
```
