# Startup capacity observation

Source: coordinator snapshot capacity-lqg-resume-20261015.json, observed 2026-10-15T07:17:26Z.
Host: 14 physical cores, 28 online logical CPUs 0-27. Controller nproc: 22; affinity: 0,1,8-27.
Cgroup v2 mount: /sys/fs/cgroup, mount root /. Membership: /user.slice/user-1000.slice/session-2050.scope.
Effective cpuset: 0-27 at root/user.slice; lower absent files inherit. Applicable user.slice,
user-1000.slice and session scopes report cpu.max = max 100000; root cpu.max is absent.
No finite quota was observed.

Observed commands: lscpu, nproc --all, nproc, taskset -pc controllerPID, reads of /proc/self/cgroup,
/proc/self/mountinfo and applicable cpuset/cpu.max files. Bounded child probe
`taskset -c 0-25 nproc` returned 26; `taskset -c 0-25 cat /proc/self/status` confirmed
Cpus_allowed_list 0-25. Controller affinity stayed unchanged. An intermediate
`taskset -pc 0` query failed and supplied no evidence.

Owner limit: max(1, total host logical CPUs - 2) = 26. Verified child work budget: 26.
Controller commands still cap at their actual 22-CPU affinity. Integration allocation 4 plus
four adapter allocations 2 total 12, below 26. Agent slots: controller + 12 children; analysis route cap 10.
No uncertainty was recorded. The runtime helper never widens affinity itself.
