# Owned local execution

`getzilla execution start --tool TOOL --intent STABLE_KEY --timeout SECONDS`
starts one existing source-pinned managed tool. It returns its registry execution
ID. `get`, `wait ID --seconds N` and `cancel ID` use the same attempt. Wait is
bounded to30seconds; an expired wait never restarts work. Timeout is1–300seconds.
First bind a native owner route and explicitly run `getzilla trust provision`
for that task. The current native session and canonical task determine ownership. No principal,
capability token, free shell command or model-provider request is a CLI input.

An armed STOP still admits the closed literal `execution get`, `wait` and
`cancel` forms through the hook. Wait uses its default or a decimal
`--seconds` in(0,30]. New starts, shell tails and extra options stay refused.
The normal secret and protected-path policy still runs for admitted controls.

The explicit `linux-pinned-local-v1` profile requires Linux pidfds and bubblewrap
with user, PID and network namespaces. The adapter checks the normal before-tool
policy and fixed executable SHA/argv before dispatch and again before release.
It retains the existing execution-store generation, task/epoch, immutable intent,
source digest, original deadline and one-use launch claim. Unpinned tools refuse.
Production callers can use `getzilla.supervised_execution.start`; the unrestricted
contract-test `execution.submit` default remains deliberately unsupported.

A transient host supervisor receives its one-use capability through a bounded
private pipe. There is no second queue or durable ledger. It launches only its
own namespace and exits after that job. CLI exit does not relaunch or stop the
supervisor. Supervisor death kills its namespace through kernel parent-death
handling; subsequent observation reports unknown cleanup until reconciled.
It never kills a saved raw PID or treats a reused PID as an owned process.

The command sees a read-only host filesystem plus its writable project, a private
PID namespace and a network namespace with no external route. This is not a
secret-store read sandbox: ordinary repository secret/protected/external-write
policy still applies to the admitted command. All inherited cloud/provider
environment variables are removed. No network fallback or paid-model dispatch
is added. A fixed tool remains trusted local code.

The supervisor and its children inherit a two-CPU affinity bound, per-process
1GiB address-space and256FD ceilings. These are not an aggregate cgroup memory
limit. At most2managed attempts
can own active slots. Unconfirmed cleanup keeps a slot reserved. Pending work is
refused instead of queued. The existing256-record registry limit retains intent
tombstones and refuses further allocation when full; it never silently forgets
an intent to rerun its effect. Preview retention uses the shared bounded execution
output contract. Counters, truncation and credential suppression remain explicit.
Live preview updates are coalesced; previews never establish evidence authority.
Cancel commits a request; only observed process termination and subreaper cleanup
produce confirmed cleanup. Stop, deadline and task revocation keep the release
gate closed or clean up the owned namespace.

`getzilla par --managed-tool TOOL --intent KEY --timeout SECONDS --wait-seconds N`
opts into the same registry backend. Repeat `--managed-tool` for at most2tools.
Each tool gets a stable indexed intent. The default synchronous shell runner is
unchanged; there is no hidden managed queue.

Linux namespace executions have local test coverage. Native macOS/Windows strict
containment and remote MCP server cancellation remain unsupported. This profile
does not implement an MCP transport or qualify all EX08 platform/resource cases.
