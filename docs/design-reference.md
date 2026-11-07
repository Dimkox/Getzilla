# Local design reference (optional)

This child of issue306 provides local D1/D3 observations. D2 browser capture remains
mandatory and open. These artifacts do not prove functionality, accessibility,
legal compliance or acceptance.

The existing installer can copy the exact passive artifact bundle with
`getzilla install-into <new-project> --materialize-new --design-reference-artifacts`.
This only distributes bytes. The default Core install copies no optional payload.
Inside an owned Getzilla project, use `getzilla design-reference install --source
<source-install>`, then `getzilla design-reference enable`. Update, disable and
uninstall use the same optional-module ownership transaction as other passive
modules. Foreign files and settings remain owned by the user. No browser adapter
or service is installed. Disabled/missing modules load no addon code, start no
workers, make no requests and spend no provider tokens.

Use an actual owned active task with an incorporated change package:
`getzilla design-reference capture --file tokens.json --file theme.css`.
Selection is explicit and project-relative. JSON scalar values and CSS custom
properties retain raw values/units, source token names, hashes and locators.
JSON pointers and CSS context/selector/property identities define stable IDs.
Values, file hashes and positional offsets do not define those IDs. Proposed
semantic names are not observed values and are not added automatically.

Bounds are16 files,256KiB/file,2MiB aggregate,4096 tokens,1MiB pack and5 seconds.
Duplicate/nonfinite JSON, ambiguous declarations and malformed/changed inputs
refuse. Unsupported structures, imports and unresolved expressions report partial
coverage; imports are never followed. JSON object keys and numeric spelling are
retained. The CSS subset supports declarations and bounded media/supports/layer/
container contexts; it does not compute styles, cascade, inherited values or
browser state. No JS/TS configuration, callbacks, network or model runs.

Version1 canonical content includes tokens, source identities, capture parameters
and coverage. Its digest excludes the run envelope's capture ID/time. Evidence is
an advisory JSON record with readable summary and relative source references,
published exclusively under the actual task's evidence/design-reference folder.
At most32 records are retained; capacity refuses instead of pruning history.
Capture IDs are unique within the actual task. Exact replay of the same full
record, including retained timestamp, returns its existing record even at capacity.
Reusing an ID with different content, timestamp or task context refuses before a
second write. A new event needs a new ID. Existing records are never replaced.
The bounded32-record history is validated before publication; unknown, malformed,
cross-task, duplicate-ID or unsafe entries cause refusal. There is no second
ledger. Existing task serialization coordinates writers; it is not OS confinement.
Older contexts/epochs from the same stable task remain historical advisory data.
Each new capture needs fresh current ownership, scope and admission. Old records
never authorize a new action or qualify a PASS. A context change needs a new ID.

`getzilla design-reference diff <previous-record-sha256> <current-record-sha256>`
reads only that task's immutable records. It compares token values and logical
origins separately from changed source-table hashes. A one-token edit does not
classify unrelated tokens as changed due to a shared file digest or line offset.

D2 still needs a separately scoped disposable browser adapter, pre-navigation
destination/method/transport enforcement, controlled click/mutation counters,
bounded DOM/responses, viewport/theme/locale/version and font/CSS/coverage facts.
Screenshots cannot prove functionality or accessibility. This local feature adds
no private/native authority and does not enable private previews. Current MIT
terms remain unchanged; draft legal decisions are not final legal approval.

The command pins the reviewed0.1.0 manifest. A different self-consistent passive
artifact is not executable authority, even with matching local ownership. New
code needs a new reviewed artifact and command pin; ownership alone is insufficient.
