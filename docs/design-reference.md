# Local design reference (optional)

This child of issue306 provides local D1/D3 observations and D2 computed styles
from caller-owned controlled loopback fixtures. Live preview capture is unsupported. These artifacts do not prove functionality, accessibility,
legal compliance or acceptance.

The existing installer can copy the exact passive artifact bundle with
`getzilla install-into <new-project> --materialize-new --design-reference-artifacts`.
This only distributes bytes. The default Core install copies no optional payload.
Inside an owned Getzilla project, use `getzilla design-reference install --source
<source-install>`, then `getzilla design-reference enable`. Update, disable and
uninstall use the same optional-module ownership transaction as other passive
modules. Foreign files and settings remain owned by the user. No browser dependency
or service is installed. An explicit fixture request uses an existing optional
Python Playwright installation and `/usr/bin/google-chrome`; missing capabilities
refuse. Core never installs or imports these dependencies. Disabled/missing modules load no addon code, start no
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
Selector admission is conservative: ASCII type/class/ID selectors, universal
selectors, ordinary attribute tests, listed simple pseudo-classes, combinators
and comma lists. Bare markers, unsupported functional/escaped/nested selectors
or other unqualified headers make coverage partial; extracted values stay raw
source observations. This is not a full stylesheet validator or CSS engine.
Context headers must match a complete supported form within512 characters:
media types `all`, `screen` or `print` (optional `only`/`not`), and/or width/height
features joined by `and`; simple supports tests for `display: grid|flex|block`;
optional named containers with width/height features; and simple dotted layer
names. Width/height features allow `min-`/`max-`, zero or nonnegative decimal
`px`/`em`/`rem` lengths. Names use ASCII identifiers and exclude reserved words.
Other forms, including complex conditions, remain partial with raw observations.

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

For a caller-owned synthetic HTTP fixture, use an explicit request:

```bash
getzilla design-reference capture-preview-fixture \
  --url http://127.0.0.1:8080/ \
  --resource http://127.0.0.1:8080/ \
  --resource http://127.0.0.1:8080/style.css \
  --width 1280 --height 720 --theme light --locale en-US
```

Each exact resource URL must be selected. Only literal `127.0.0.1` HTTP origins
with an explicit nonprivileged port are accepted; alternate destinations,
credentials, fragments and redirects refuse. Do not point this command at an
internal or production server. Even GET can have server effects. Caller ownership
of the fixture is a precondition; the command does not establish source rights.

The separately admitted optional `preview.py` adapter starts a new sandboxed Chrome context without user cookies. Before
page creation, it blocks service workers and WebSockets and installs interception.
It permits only declared GET document, stylesheet, font, image and script reads.
It denies fetch/XHR/beacon, unsafe methods, redirects, frames with another URL,
and unselected resources. It never clicks, submits or authenticates. A standard
library client reads each permitted resource without forwarding browser headers,
cookies or authentication. It supplies bounded bytes to the browser; it never
continues a browser request to the network. Only content type is retained from
response headers. This is an application policy, not OS network confinement.
Browser routing does not cover every background/UDP transport. Live capture
therefore remains unsupported; this is no universal read-only guarantee.

Version2 packs record viewport/theme/locale, browser and Playwright versions,
response hashes, computed values and document-order element locators, CSS/font
loading state, capture ID/time, and coverage reasons. Stable IDs use the page URL,
element position and property. DOM insertion can change positional identities;
these are observations, not inferred semantic roles. The twelve observed
properties cover colors, type, selected spacing, radius and shadow. No hover or
other active state is induced. No screenshots are captured.

Bounds are16 declared URLs,32 reads,256KiB per response,1MiB total response bytes,
128 elements,1536 observations,4096 characters/value,1MiB pack,1 second per network
operation,4 seconds for navigation,8 seconds for accepting reads, and15 seconds
for the whole worker. After the deadline, Linux pidfds stop the worker and observed descendants.
A bounded monitor records parent chains and process birth identities before any
signal. Controlled-fixture tests check that no observed browser descendant keeps
running; this does not provide OS process confinement or universal supervision
of an adversarial process that escapes before observation. Failure to launch with the sandbox enabled refuses;
there is no no-sandbox fallback. Other platforms are unsupported.

Missing CSS/fonts, blocked transport, dynamic content and exceeded budgets report
partial coverage or refuse. Every fixture pack is partial with `fixture-only` and
`dynamic-unproven`: a short observation cannot prove no later DOM changes. The
content digest excludes capture ID/time. Version1 local packs keep their schema.
Both variants use the same task-bound immutable history and diff command. URL
source hashes describe captured response bytes and are not reread as local files.
Screenshots and style observations cannot prove functionality or accessibility.
This feature adds no private/native authority and does not enable private previews.
Current MIT terms remain unchanged. No upstream implementation code was copied.

Browser tests are optional and explicit:
`GETZILLA_DESIGN_BROWSER_TESTS=1 python3 -m unittest tests.test_design_reference`.
The default suite runs browser-independent controls and skips fixture launches.
The adapter uses [Playwright routing and isolation](https://playwright.dev/python/docs/api/class-browsercontext)
and [response fulfillment](https://playwright.dev/python/docs/api/class-route#route-fulfill).

The command pins the reviewed0.1.0 manifest. A different self-consistent passive
artifact is not executable authority, even with matching local ownership. New
code needs a new reviewed artifact and command pin; ownership alone is insufficient.

The architecture keeps `reference.py` in the existing no-network local policy
component. Only explicit preview requests load `preview.py`, which has a separate
optional node and a declared local TCP/HTTP edge to a caller-owned synthetic fixture.
The Core node, network rules and global budgets are unchanged.
