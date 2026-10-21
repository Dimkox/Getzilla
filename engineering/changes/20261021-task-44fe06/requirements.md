# Requirements

Typed criteria AC-001 through AC-006 in change-spec.yaml govern this candidate.

- Matrix review is valid through day180. Missing, malformed, future or older metadata yields MATRIX_STALE REVIEW, including an empty registry. Disabled projects still skip.
- Risk scores are optional strict integers1–5. High residual risk requires accepted_by confirmation. Check next_review only when the obligation applies. Original four-field risks remain valid.
- Scaffold validates the final adapter against its system glob. Reject ambiguous, file-only, traversing and symlink paths. Create exclusively. Keep the registry unchanged.
- Python and Node adapters return caller-supplied public provenance. C2PA output is distinct; missing tools, failure and timeout preserve input. Returned metadata alone is not embedded marking.
- CI check needs committed opt-in and exact base, emits stdout evidence only, and uses no receipt. Normal bundles keep receipt requirements. Signed execution requires exact head/base/repository, passed status and successful actual audit argv with integer exit0.
- ISO mapping is optional and never affects gating. Document static symbol and generic verification limits.

Security evidence comes from code/test/security/release reviews of the committed candidate. No external mutations, new services or telemetry are added. Repeated scaffold calls fail before overwrite. Existing architecture and governance rules remain authoritative.

Repair boundary: scaffold requires descriptor-relative safe creation and refuses before mutation on Windows. Operators can copy either installed template manually. Bind compliance.json, obligations.json, ai-systems.json, diff-risk-rules.json and cost-providers.json to committed inputs; only the registry may be absent in both Git and disk for enabled audits. Preserve ordinary --root by passing explicit inputs. The Node timeout must terminate a real child that ignores SIGTERM.
