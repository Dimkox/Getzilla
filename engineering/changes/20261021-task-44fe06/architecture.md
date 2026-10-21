# Architecture

Typed authority: change-spec.yaml. Core stays in its existing subsystem. No service, database, queue or new dependency is added.

The opt-in gate loads the matrix and registry. It reads code, tests and risk records from the selected Git commit. Matrix freshness adds REVIEW. Optional risk checks extend the current validator.

The scaffold reads the system registry, validates a single destination, and writes an adapter with existing fsx no-follow directory handles and exclusive creation. Node/Python adapters use only caller labels and optional bounded C2PA execution. They never replace the source media.

The audit wrapper separates ordinary local receipt-based bundles from read-only CI evidence. It rejects uncommitted compliance inputs. It invokes a caller-selected trusted installed attestation verifier outside the project, with fixed argv, a safe cwd, a minimal environment, a timeout and an output limit. It does not import Trust CI. Signature verification precedes identity and exact command checks. Attestation evidence covers execution, not regenerated bundle bytes.

The closed v1 signed-result schema stays byte-identical. A new v2 envelope binds payload schema_version2 and optional bounded argv. Its architecture contract has exact compatibility and version2. Upgrade verifiers and schema consumers before producer emission. A separate Trust CI candidate owns the producer and opt-in policy command. FIT-TRUST-CI-SEPARATION and FIT-SIGNED-PAYLOAD-EXACT remain unchanged.

ISO mapping is a project-authored clause-level aid under compliance.iso42001 with gating:false. Its absence or malformed content cannot affect decisions. Source check metadata is automated, never a claimed human review. Fictional examples are labelled.

Main risks: forged execution claims, uncommitted control inputs, scaffold path escape, metadata disclosure and overstatement of compliance. Boundaries and negative tests cover these risks. No Bitrix component or deployed policy changes.
