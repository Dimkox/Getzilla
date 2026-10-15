# Architecture — GZ-HOOK-ROOT-001

> Typed authority: [change-spec.yaml](change-spec.yaml).

The first incorrect state was `_command_directory_aliases`: a regex saw shell operators inside quotes and returned `command.control-flow=<ambiguous>`. The root resolver then rejected the command before explicit workdir resolution. A second regex split the same quoted data in `_command_chunks`, causing malformed fragments and ambiguous authority. `_simple_commands` also treated quoted operator words as syntax after shlex removed their quotes.

`_shell_tokens` now scans quotes and escapes once. Each token retains decoded value, original offsets, operator status and active expansion/substitution flags. It does not execute or expand text. Root inference consumes provenance. Authority and shell mutation analysis split only at actual operator offsets. Simple-command and environment analysis retain the same operator flag.

The wrapper and interpreter analyzers keep their existing scope. Literal nested shell payloads are scanned again as code. Active substitutions and unsupported root grammar fail closed. The parser does not become a general shell evaluator. Existing `env` denial, dynamic authority selector checks and bounded wrapper depth remain unchanged.

Denial diagnostics add the actual hook, root parser and policy parser paths with SHA-256 hashes. Session root, effective root and resolution status stay separate. Command-derived root values are redacted. Source field names identify the failed stage. The existing command digest remains. The circuit breaker only records a decision already made; no counter, TTL, fingerprint or authorization rule changes.

The base already contains native cmd normalization and nearest launcher selection from PR #79. Compaction does not cache or alter root inference. Source registration provenance is a static configuration observation; no live hook process capture is claimed.

Rollback needs no data migration. Revert this source change in an isolated PR or make a bounded forward fix. Run the same guard suite and exact-head gates before any install.
