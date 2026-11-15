# Ignored runtime state caused a source-inventory race

Issue #416 reproduces a separate installer defect: a generated runtime entry can
disappear after directory enumeration, before the metadata read that precedes its
existing exclusion. New tiny file and directory fixtures deterministically hit
that refusal. Skip only the already ignored runtime descendants before metadata
access, after path validation. Keep the runtime root bound, mandatory sentinels
checked, and managed-source disappearance, link, type, identity and resource guards.

The earlier full run on98b7426e retained the enumeration metadata guard but omitted
the missing path and errno. This new reproduction does not establish that earlier
path or cause. Compare known source guards with a new deterministic fixture; do
not infer an old cause from a similar failure or replay the full workload to guess.
