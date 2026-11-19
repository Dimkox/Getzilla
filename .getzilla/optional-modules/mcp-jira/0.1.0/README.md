# Optional managed MCP/Jira source

This artifact is outside Core and its engine archive. Install does not enable it.
The existing module lifecycle requires explicit project activation and trusted
native authority/runtime ports. Activation selects an explicit subset of declared
permissions; a `jira.read` activation cannot create a write intent. A separately
authorized `jira.write` grant still does not qualify a mutation provider. A disabled or pending module starts no worker,
reads no credential, registers no server, and makes no request. Existing user MCP
configuration is untouched; this profile requires no native registration.

One activation may name up to 16 explicitly scoped stdio servers; each call selects
only a named server from that bound scope. Aliases do not create new budgets.
The supported profile is Linux managed stdio, MCP `2025-11-25`, with an explicitly
pinned executable/argv and expected server version. It uses the existing canonical
execution admission, source/owner fences, IDs, deadline, cancellation and cleanup.
A dedicated subreaper owns a private PID/user/network namespace. A separate launch
gate leaves stdio available for MCP. No source path, PID, allow flag or credential
from a tool request can create this authority. Direct native calls are unmanaged;
ordinary hooks still refuse unqualified `mcp__` identities.

`Runtime.call` invokes the source-trust port before admission. Installed bytes,
manifest/dependency identity, executable pin, module/protocol/server version and
nonsecret credential scope must match. Only the actual local OS UID scope is
qualified by this no-auth stdio profile; arbitrary credential aliases and remote
credential profiles are unsupported. The actual handshake and bounded
`tools/list` pages precede `tools/call`; unknown versions, schemas, pagination and
non-read capabilities remain unsupported. Stdio uses the official newline JSON-RPC
framing [contract](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
The 1 MiB aggregate response cap is checked before accumulation and JSON parsing,
including binary/base64 fields. Stderr never counts as a response or receipt.

A trusted host inventory supplies `HostBudget`. It reads existing canonical stores
and holds one bounded runtime lock only around atomic allocation. It adds no
execution registry or queue. The versioned `resource-budget-v1` feature separates
MCP request ownership from ordinary supervised local checks. Core keeps its
default local ceiling of two; the trusted MCP backend has a ceiling of eight
with the stricter scoped/host admission port. Older Core refuses the required
feature instead of silently dropping the limit. Limits are two active/unconfirmed local attempts per
actual executable/argv + project + credential scope, eight across that host
inventory, and 32 unresolved remote tasks. Display aliases do not change the key.
Missing inventory blocks admission. Saturation returns `resource_busy`.

Canonical infrastructure outcomes implement three failures within 60 seconds,
60-second cooldown and one read-only half-open probe. Domain responses, policy
refusals, user cancellation and wait expiry do not charge health. No automatic
retry/reconnect is enabled. Progress cannot extend the finite hard deadline.
MCP request IDs, execution IDs and remote task IDs stay separate. Task profiles
without qualified polling remain explicitly unsupported; remote uncertainty is
retained. Local cleanup never becomes a remote cancellation receipt. Slots remain
charged until owned local cleanup is confirmed.

The bounded Jira adapter applies the same exact site/project/resource/operation
check to ordinary and nested dispatcher calls. Read results require the host's
per-source access-admission port before release. The optional effect projection
is keyed to existing execution/operation IDs. It records intent before a qualified
provider can emit, never repeats inflight/unknown effects, and reconciles through
current permission checks without undoing human changes. Closure still requires
the native accepted-change/AC evidence port; caller checkboxes are insufficient.
The managed stdio profile itself admits reads only. The effect-provider test port
is not a production Jira qualification.

Official Atlassian Streamable HTTP/OAuth, real Jira tool aliases, provider-specific
pagination/429 policy, mutation preconditions/ADF conversion, actual permission
mapping and the II Tonya pilot remain NOT_TESTED. No connector token is reused and
no hidden REST fallback exists. macOS/Windows and modern MCP protocol profiles are
unsupported. Fake local peers and Linux tests prove only the stated local profile.
Disabling stops admission and owned workers via the existing lifecycle; evidence
and unknown remote outcomes survive. An unconfirmed startup/cleanup remains
quiescing rather than receiving a fabricated zero-worker proof.
