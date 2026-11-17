# Current managed software

The bootstrap resolves current final upstream releases on every invocation. The
stored `built` values describe historical test versions. Doctor checks actual
command exit status, branded version and path against minimum requirements. A
minimum check does not establish freshness.

`getzilla install-managed --home <Getzilla checkout> --agent qwen` installs exact
current Python/Git/Node/npm and the selected agent. Repeat `--tool composer`,
`--tool cosign`, or another declared optional tool. Composer also requires current
PHP. `--environment-only` creates Getzilla's isolated quality/test environment;
`--verify-only` checks final actual versions and PATH. Customer requirements do
not enter this environment. Provider credentials and sign-in remain separate.

The updater owns public HTTPS acquisition. It binds official release identity,
asset origin and published SHA256 or SHA512 before activation. npm and Python
resolve exact direct targets before dependency resolution; incompatible newest
targets do not fall back to older compatible releases. GitHub tag inspection
checks higher numeric final releases rather than assuming the default latest
pointer is the highest maintained major. OpenGrep consumers rederive official
integrity; a writable local hash record cannot authorize scanner code.

Metadata has finite source-local bounds. Ordinary JSON is at most 2 MiB. Full
PyPI project catalogs allow 64 MiB decoded and 2 MiB gzip wire data (or 64 MiB
identity data); the observed coverage catalog alone exceeded 8 MiB. Selection
uses the complete final release catalog, including epochs and post releases,
not the latest compatible wheel. A bound, format or integrity failure reports
incomplete. Existing workflow generation limits remain unchanged.

`getzilla baseline apply --project <directory> --agent qwen` resolves official
workflow releases and exact Git objects, then materializes verified source data.
An identical current source can reuse shipped bound assets. New Superpowers
skills and supported Spec Kit templates/scripts use closed data adapters. The
publisher checks native policy and managed file CAS. It preserves user edits and
refuses unproved ownership. Imported prose grants no permissions or semantic
approval. New unknown BMAD generator formats stay incomplete; old payloads never
count as the new release.

Grok's published installer does not establish an expected artifact checksum.
Claude's signed newest-channel adapter is not established by this implementation.
Those selections stay incomplete. Unix PHP and Docker service activation also
require a supported explicit adapter. Source-built Python/Git verify published
SHA256 over official HTTPS; GPG/Sigstore material is not claimed verified. These
limits are reported and are not waivers. Real Windows non-admin installation and
the final integrated gate require separate execution evidence.
