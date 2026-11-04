# Optional modules

Optional modules share the existing `getzilla components` ownership ledger and
writer guard. Core installs none and enables none. The default registry is empty.
No Jira provider, design-token pack, browser, video model or Enterprise feature
is supplied by this lifecycle foundation.

Inspect the catalog or the installed project:

```bash
getzilla components module registry
getzilla components module status --project <project>
```

After selecting a trusted local catalog with a real package:

```bash
getzilla components module install <id>@<version> --project <project> --source <catalog-root> --plan
getzilla components module install <id>@<version> --project <project> --source <catalog-root>
getzilla components module enable <id> --project <project> --grant <declared-scope>
getzilla components module disable <id> --project <project>
getzilla components module update <id>@<new-version> --project <project> --source <catalog-root>
getzilla components module uninstall <id> --project <project>
```

`--grant` repeats for each scope. Enabling a module includes its exact module
dependencies and needs the union of their declared scopes. It does not register
or connect a native client. Each future provider owns that explicit step.
Installation, status and update do not enable modules. Updates disable affected
modules and clear grants. Another project keeps its own activation state.

`--source` selects a local catalog root. `--registry` selects a file relative to
that root; the default is `.getzilla/config/optional-modules.json`. Default source
selection uses the local full Getzilla checkout. No network fetch, authentication,
provider import or dependency-manager command runs. Select and trust a registry
before using its hashes; checksums alone do not authenticate a publisher.

The [registry schema](../schemas/optional-module-registry-v1.schema.json) pins
publishers, allowed license identifiers and exact versioned manifest hashes.
Artifacts live at `.getzilla/optional-modules/<id>/<version>/module.json`.
The [module schema](../schemas/optional-module-v1.schema.json) declares:

- A module ID, exact version and publisher matching the registry.
- A supported Core API interval; the current API is 1.
- Exact dependency versions, declared permission scopes and a license.
- An optional licensed capability, verified by a trusted local entitlement adapter.
- `hooks: "declarative-v1"`; executable hooks and background workers are unsupported.
- Files with relative paths, SHA-256, mode `420` (0644) or `493` (0755), and a `mutable` flag.

Include a hashed `LICENSE` file. IDs are lowercase names with hyphens. Versions
use three numeric components. Files cannot replace `module.json`, collide by
case, traverse parents, use reserved device names or be links/hardlinks. Missing,
corrupt, incompatible or conflicting artifacts are refused before product writes.
Semantic loader checks add cross-field, namespace and compatibility validation to
the published JSON shape.

Installed files stay under `.getzilla/modules/<id>/`. The ordinary v2 component
ledger records exact byte/mode ownership and separate enabled/grant metadata.
Existing adapters, extras, compliance and factory selection retain their current
commands and behavior. Generic modules do not implicitly adopt legacy state.

Core-only payloads and engine archives exclude addon artifacts and provider code.
Core updates preserve module records and project-owned registry configuration.
Harness generation leaves module records and unrelated native-client entries
alone. Generic lifecycle never authenticates with or changes user-owned credentials. Mutable module
settings and unknown files remain user-owned. Edited immutable files refuse an
update; uninstall preserves them and removes only unchanged owned bytes/modes.
No recursive directory removal occurs.

Licensed operations use the same lifecycle. A trusted local entitlement verifier
must return verified admission for the exact project, module, version and licensed
capability. CLI has no entitlement override and refuses such admission without
that adapter. Community operations do not call it. A local scope grant never
creates Jira write, production or security approval authority.

## Recovery

The writer guard serializes cooperating component operations. Individual file
publication is atomic; a group of files is not a filesystem transaction. A bounded
journal is saved before the first product write. On failure the lifecycle tries
to restore matching old/new bytes. An intervening user edit is preserved and
leaves recovery pending. Pending recovery refuses module admission.

```bash
getzilla components module recover --project <project>
getzilla components module rollback --project <project>
```

Recovery can be retried. Rollback covers the latest lifecycle operation and
requires its expected ledger. It honors current kept-local declarations and
clears activation/grants. It cannot revive revoked permissions or overwrite a
later Core/module change. Inspect a reported conflict before retrying; do not
replace user bytes to make a journal look successful.

Limits: 32 catalog modules, 32 versions per module, 128 files per artifact,
1 MiB per artifact input, 4 MiB of changed before/after payload per operation,
16 MiB per recovery journal and 32 retained history entries. At capacity, retain
or archive the evidence explicitly before a later install, update or uninstall.
Disable remains available at history capacity. Such a revocation retains no new
rollback entry and reports `rollback_available: false`; prior history is preserved. Exact dependency
pins resolve locally; cycles, conflicts and removal of a required dependency are
refused. No SDK, package manager, model or external runtime is installed.

See [ADR 0003](../engineering/adr/0003-optional-module-lifecycle.md). The test suite
measures actual Core install time and bytes, module payload/dependency footprint,
and zero external dependency installations. These local observations do not
qualify a future provider or replace the existing verifier and exact-head CI.
