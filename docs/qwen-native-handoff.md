# Selected local Qwen handoff — default off

This is a conditional native-host transport slice for #235. It does not qualify a model, activate a service or enable the six-client rotator. Native writer/session rotation, stopping a prior native writer and replaying tools remain unsupported. The delivered slice performs a **new-session, no-tools local context handoff**. It returns bounded model bytes to the trusted parent, not a task-acceptance decision.

## Actual authority path

A trusted parent can construct `QwenNativeHandoff` only with all of these existing resources:

- The actual `FactoryNativeAccessHost`, actual host-issued `PreparedReadResponse` and its retained private `_PreparedBinding`. A DTO or payload checksum cannot replace them.
- The opt-in151 `PayloadProfile` named `factory.local-public-context151/v1`. The registered source must be PUBLIC. The existing producer retains the exact transformed bytes, complete source/class/policy lineage and original native principal. The sink calls the same source/permission revalidation before claiming and after the response.
- An existing server-owned `AdapterRegistry` which actually resolves the selected Qwen reader profile. No eligible Qwen registry is created here. The closed profile pins Qwen 0.24.7, native tree digest `a571388bb0810112a3120693da7abcee63a2d5c1070a8618bd2ca3a883b0a924`, model `qwen3:1.7b` and native-worker proxy destination `http://127.0.0.1:11435/v1/chat/completions`. A wire `eligible:true` is insufficient.
- The owned Core route with its existing153 budget, and a held real native network-namespace FD. The running trusted gateway must share that exact namespace at each current-authority check. The parent must qualify ownership/isolation of that namespace and the selected backend; an arbitrary current-namespace FD does not establish qualification.

The parent must bind the private UDS path/token as the existing `UdsResultHandoffClient` destination. `serve_once` accepts one bounded request from the same OS UID with the exact bearer token and operation headers. It verifies the complete retained envelope, repository/task/run, fence, packet and immutable attempt identity. It does not accept caller-selected paths, endpoints, models, tools, callbacks or account credentials. Missing dependencies/profile qualification remain closed.

The original `AccessReleaseService` performs ResultBroker admission, source checks and its protected outbox claim before delivering the UDS frame. Migration029 adds one irreversible native-forward claim to **that same outbox row**. It verifies the protected sending state, original native principal, source binding, current task/stop/fence/attempt and exact persisted reader execution selection. There is no second queue or retry journal. Earlier migration bytes remain unchanged.

Before the local request, the sink reserves and claims one canonical153 operation. Its key binds operation, attempt/fence/source through the full envelope, selected profile and exact request bytes. Limits do not reset when the process restarts. Unknown CPU/token measurements retain their reservations. A completed local response can settle the observed request with known zero provider charge and measured elapsed time; it does not invent CPU/token usage or human acceptance.

## Exact network direction

Measured qualification topology is:

`untrusted Qwen worker → proxy11435 → trusted backend11434`

The native worker remains restricted to11435. The **trusted final UDS sink** calls fixed `http://127.0.0.1:11434/v1/chat/completions` in the same held private namespace. It must run outside the untrusted worker's Landlock restrictions. Do not widen the worker to reach11434. Sending this final hop back to11435 can recurse through a gateway. The existing measured native-worker proof does not automatically qualify this new UDS stage.

The request uses only151-retained public documents as untrusted user data. Its fixed system instruction requests a summary. It sets `model=qwen3:1.7b`, `stream=false`, `max_tokens=768`, `temperature=0` and exposes no tools. It never replays a tool attempt or claims hidden-reasoning/session transfer. The registered selected profile must match the actual persisted Factory execution packet; a different model/profile cannot borrow the source release.

The transport uses a literal loopback IP, no ambient proxy, no DNS, redirects, credential lookup or retry. Header count/bytes, request body, response body and every socket read have bounds under one absolute deadline. The existing151 deadline remains authoritative; the local forward is at most1.5seconds and `serve_once` at most2seconds. A slow local model yields unknown, not an unbounded wait. Current framing requires a bounded Content-Length JSON response; unsupported/chunked frames remain unknown pending exact-profile qualification.

## Ambiguity and rollback

The outbox claim commits before local HTTP. Duplicate callbacks, a crash after claim, a lost response, expired source authority, a cancelled task or an old generation cannot cause another send. A failure after claim leaves an unknown effect/spend for reconciliation. No function clears the native-forward marker or blindly retries. Disabling/removing the composition preserves outbox and budget evidence. The sink closes its owned sockets, removes only its own unchanged private UDS entry and releases its held namespace FD through `close()`.

A successful handoff postcondition establishes that this local request returned a validated bounded model response. It is not evidence of model quality, native writer eligibility, source acquisition consent outside151, external attribution, accepted work or a complete #235 rotator. Normal startup status and unknown-client matrix rows remain unchanged and unavailable.

## Evidence and remaining qualification

Offline checks use synthetic source/authority/store fixtures. They cover stale/cancelled/malformed identities, post-claim revocation, duplicate/lost-response/crash holds, framing limits, fixed routing and redirect refusal. A real bounded socket test sends authenticated UDS data to an owned **fake HTTP backend**, with no model call. Another real UDS test rejects a bad token and checks socket cleanup. Those tests do not qualify native/profile authority.

Run:

```sh
PYTHONPATH=factory/src:.getzilla taskset -c 2 python3 -m unittest discover -s factory/tests -p test_qwen_native_handoff.py
PYTHONPATH=factory/src:.getzilla taskset -c 2 python3 -m unittest discover -s factory/tests -p test_migrations.py
```

Actual151 principal/source/profile integration, migration029 PostgreSQL execution/concurrency, real Qwen/Ollama completion through this UDS stage, private-namespace ownership, model usefulness, native-writer stop/fence and six-client continuation remain **NOT_TESTED**. Model qualification is a separate prerequisite. No real marketing/collector/provider request, paid session, secret read, CI run, production activation or push is established here.

Official [Qwen headless documentation](https://qwenlm.github.io/qwen-code-docs/en/users/features/headless/) was consulted on2026-11-19. Installed-version and host behavior still require their own evidence.
