# Model, tool and MCP trust audit and design (#156)

This audit covers source at `374b120be90a24478f02234dd3a14d074921dae0`.
It maps the existing controls to issue #156. It adds no authority or runtime
service. A source audit does not qualify an installed tool, live provider,
credential, model weight, remote endpoint or active stop mechanism.

## Existing owners and supported paths

| Concern | Actual owner and consumer | Boundary |
| --- | --- | --- |
| Closed source inventory | `.getzilla/getzilla/supply_chain.py:audit` | Reads bounded public source files without executing them. Reports declarations, not installed identity or trust. |
| Hook admission | `policy.py` calls `supply_chain.check_tool_trust` | Unknown MCP calls fail closed. A policy entry or exact write grant does not prove endpoint identity. |
| Managed MCP identity | `.getzilla/optional-modules/mcp-jira/0.1.0/runtime.py:Runtime.attest_tool` and `Runtime.call` | Rechecks current activation, installed/executing source bytes, executable digest, server version, module dependencies, host bootstrap/sandbox digests and local UID credential scope. Only the bounded managed stdio read profile is supported. |
| Least privilege | MCP `Runtime.call`, `module_runtime.py` and `optional_modules.py` | Requires actual activation authority, current owner/generation, explicit operations and matching scope. Read activation cannot grant write effects. Remote and unsupported profiles stay unqualified. |
| Model list pins | `factory/src/getzilla_factory/model_rotator_registry.py` | Default-off immutable candidate list, upstream commit, archive and models-file hashes. It owns no client, credentials or activation. Alias pins do not pin served weights. |
| Factory stop | `factory_stop.py`, `service.py` and `landing_live_executors.py` | Actual service/store issues an opaque capability tied to actor, repository, task, job and content. Global/repository revision changes and authority outages fence that capability. Live executors check before credential use, effects and result publication. |
| MCP stop and availability | MCP `Runtime.current`, `Runtime.quiesce`, `admission.py`, `transport.py` | Durable disable fences admission and reply release. Owned children receive cancellation. Bounded budgets, circuit breakers and deadlines isolate unavailable tools. Unknown remote outcomes stay unknown. |
| Rollback | `optional_modules.rollback_modules` and `module_runtime.py` | Update requires quiescence. Rollback restores artifact version but leaves runtime disabled, removes grants and clears generation. It does not undo a remote effect. |

## Bounded design

Retain these owners. Do not add a universal registry, permission store, stop
ledger or orchestrator. Use the existing source inventory for audit and the
actual selected native port for admission. A caller-supplied name, digest or
JSON record cannot replace that port or its activation authority.

For supported managed MCP reads, preserve the order: current activation and
identity checks, operation and credential-scope checks, bounded execution,
then current-state checks before release. Reject changed source, executable,
profile, version or owner. Disable and quiesce the actual module before an
update. Roll back through the existing module lifecycle and require fresh
activation; do not restore old grants.

For Factory landing work, preserve the service-issued stop capability and
its repository/global revision checks at the existing effect boundaries.
An unavailable stop authority must block work. Do not transfer this capability
to an unrelated model or tool path. The model registry is a source snapshot,
not a stop authority or permission to call a provider.

These scopes differ. A Factory stop does not establish that an arbitrary
external MCP endpoint stopped. MCP child cleanup does not confirm remote
cancellation. The model registry alone cannot stop an active model request.
Preserve unknown outcomes and existing effect/reconciliation records; never
clear them to regain attempts. Source rollback uses a reviewed revert and
retains those records.

## Negative controls

The existing tests provide the following reproducible source controls:

- `tests/test_supply_chain.py`: configured provenance claims, exact write
  grants and corrupt policy cannot trust an endpoint; unknown MCP calls stay
  blocked across normalized clients while local reads remain usable.
- `tests/test_supply_chain_boundaries.py`: unsafe source custody, replacement
  and mutation cannot export a qualified source digest.
- `tests/test_optional_mcp.py`: version/profile tampering fails identity;
  disabled modules start no provider work; disable before reply release
  suppresses it; T27 stops owned children and preserves uncertain outcomes.
  Wire and admission tests cover unavailable children, deadlines and breakers.
- `tests/test_module_runtime.py`: update and rollback never restore grants;
  stale plans and foreign project requests publish no activation.
- `factory/tests/test_model_rotator_registry.py`: provenance/list mutation,
  weak models and impure import behavior are rejected.
- `factory/tests/test_factory_stop.py`: unbound execution fails before
  credentials. Database-bound cases cover revocation during credential load,
  off/on/off revision fencing, unavailable authority and late result release.

These tests use owned fixtures, fake MCP children and test authorities. They
do not make a fixture registry trusted in production. Database-bound Factory
cases require the existing bound disposable PostgreSQL harness; a skipped
case is not a pass. Bounded run results belong in the change evidence, not in
an operational trust claim.

## Remaining operator qualification

Keep optional providers disabled without real selected activation authority.
An operator must establish the supported installed identity, exact profile,
credential scope and actual authority before live use. This audit neither
reads credentials nor invents an issuer, key or approval. External MCP
endpoints remain untrusted by default. Served model weights, arbitrary remote
stop guarantees and unsupported native profiles remain unqualified. No live
provider, App, service or external mutation was activated for this audit.
