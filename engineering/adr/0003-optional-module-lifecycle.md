# ADR 0003: explicit optional module lifecycle

Status: proposed source contract for issue #166. Core API version: 1.

Existing mechanisms were mapped before implementation. `component_state` provides
selected adapter state, byte/mode ownership proofs, directory bindings and an
advisory writer lock. `on_demand` performs whole-batch preflight and atomic
per-file publication. The updater preserves unrelated component records. Harness
regeneration limits retirements to selected adapter paths. These mechanisms do
not provide generic module compatibility, dependency resolution, activation or
multi-file recovery.

Use this existing ownership and writer boundary for optional modules. Extend the
closed v2 ledger with `module:<id>` records. Keep v1/v2 legacy adapter behavior
unchanged; generic modules require explicit v2 selection. Do not infer adoption
or migrate old extras into invented module activation state.

A trusted local registry pins raw module-manifest hashes, publishers and exact
versions. A manifest pins file hashes, a Core API interval, exact module dependency
pins, declared permission scopes, license and optional licensed capability.
Registry selection establishes trust; hashes then establish integrity. Hashes do
not authenticate a publisher. No signing or remote-download adapter is simulated.
Downloaded artifacts must first enter an explicitly trusted local catalog.

The default catalog contains no modules. This change ships no Jira provider,
design-token pack, browser adapter, video pipeline or Enterprise implementation.
Those consumers register real packages through this contract. Their artifacts
stay outside Core under `.getzilla/optional-modules/` before installation and
`.getzilla/modules/<id>/` after installation. Both trees are excluded from Core
payload inventory, including full-layout installs. Archive construction also
filters existing optional engine packages by the selected component set.

Installation is disabled. Activation needs a separate per-project command and
exact declared scope grants. Updates and rollback clear affected activation and
grants. Admission rechecks files, dependencies, compatible Core API and licensed
capability. It gives no external-write or authentication authority. Licensed
admission uses an injected trusted local verifier; a manifest value, license text
or CLI boolean cannot grant entitlement. No entitlement service or SDK enters
Core, and Community operations do not invoke that verifier.

Lifecycle hooks are fixed declarative actions. Generic lifecycle code does not
import module code, install language packages, authenticate, register native
clients, spend tokens or start workers. Zero orphaned workers in this version
means workers cannot be launched. Future worker-owning providers need a separate
qualified termination contract.

Keep configuration, credentials, native-client settings and unknown files owned
by the user. Generic lifecycle leaves native settings byte-for-byte unchanged.
Mutable module config can remain unowned. Immutable conflicts refuse an update.
Uninstall removes only exact owned bytes/modes and never recursively deletes a
directory. Native-client registration and its scoped merge/removal remain #207
work. Browser installation remains separate #306 work.

Before any effect, preflight the whole batch and kept-local declarations; repeat
under the existing writer guard. A bounded ignored pending journal records both
file states and the ledger before product writes. Recovery restores only known
before/after states. An intervening user change causes refusal and retained
recovery evidence. Pending recovery blocks module admission. Last-operation
rollback requires the expected ledger and honors current keep declarations. It
never restores stale grants. Disable remains possible at history capacity without
adding or deleting history; that revocation explicitly has no rollback entry. Journal checksums detect corruption, not hostile
same-user forgery. The component boundary remains cooperative, not an OS sandbox.

Rejected approaches: a second installer would duplicate ownership and recovery
rules. Executable artifact hooks would allow unbounded process/network effects.
Mandatory provider/browser/video SDKs would break Core isolation.

Validation includes real Core-only install time/disk measurements, dependency and
payload byte counts, native settings preservation across lifecycle/Core update
and harness regeneration, dependency conflicts, incompatible API, malicious
artifact and failure-injection controls. Measurements are local observations,
not paid-provider qualification, release acceptance or external merge authority.
