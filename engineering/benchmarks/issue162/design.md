# Retrieval design at pinned Getzilla 8352756

Keep exact source provenance as the shared contract for all retrieval methods. Add ranked retrieval as a later opt-in local feature. This experiment changes no installed product code.

## Audit

The existing Python AST graph records symbols, imports, calls, spans and explicit gaps. It is a navigation and conservative impact tool. It is not an embedding index. `code_graph/builder.py` resolves relationships across the approved scope and deduplicates symbols by their graph identity. `python_parser.py` reports encoding, syntax and size failures as incomplete. It does not execute source.

`code_graph/incremental.py` reuses unchanged parsed files by path, digest and configuration. It rebuilds resolution over the whole scope. `code_graph/store.py` publishes generations with an expected active-generation check, a transaction, readback validation and recovery from corrupt cache files. These are useful lifecycle patterns. They do not provide ranked retrieval or a tenant boundary. The audited pinned runtime has no native BM25, embedding search or jscpd adapter. This statement applies only to the pinned snapshot. A separate product task can change that state.

`project_ingestion.py` handles Git and plain folders. It rejects ambiguous declarations and folders inside another repository. Retrieval must accept explicit source manifests in both modes. `factory/src/getzilla_factory/context_contracts.py` was inspected by the route analysis. Its source and tenant bindings are useful, but its base/head SHA requirement needs a versioned Gitless alternative. It lies outside this experiment's retrieval candidate scope.

## Choices

| Method | Useful signal | Main limit |
| --- | --- | --- |
| Exact identifier or qualified name | Precise known symbol lookup | A behavior paraphrase may contain no symbol |
| BM25 | Rare code terms and identifier fragments | Vocabulary mismatch |
| Local MiniLM cosine | Similar language and behavior descriptions | Generic model, bounded input, extra CPU and disk |
| Equal-weight RRF | Combines ranks without score calibration | Fixed weights need wider validation; score is not confidence |
| Existing AST graph | Callers, imports, exact spans and conservative impact | Static resolution has explicit gaps; it is not a relevance score |
| jscpd | Token-based duplicate candidates | Clone similarity does not prove semantic equivalence or retrieval relevance |

Use a common immutable source inventory. Give each implementation declaration a stable identity that includes its path and inclusive span. Keep overload declarations separate from implementations. Use bounded line windows with overlap for encoders. Keep full source byte provenance for every window. Never invent a native graph feature to stand in for an embedding measurement.

The first product prototype should expose each component rank separately and make fusion optional. Keep lexical and symbol retrieval available when the model is absent. Do not set a universal cosine answerability threshold from these controls. The experiment compares fixed candidates; it does not decide whether a user question has an answer.

## Result and trusted-read contract

Return `corpus_id`, tenant, repository, source commit or snapshot identity, relative path, full-file SHA256, inclusive range, chunk SHA256, symbol kind, schema, config digest and model revision. Keep component scores and ranks separate. Mark RRF scores as rank-fusion values, never confidence.

Filter tenant, repository, approved path set and generation before ranking and before reading. Bind cache keys to the same partition, source manifest, configuration and model. Resolve paths below an approved root. Reject traversal, symlinks, missing and nonregular files, stale hashes, forged ranges and changed chunk bytes. Read source as untrusted text. Never execute retrieved instructions or expand permissions. The experimental reader checks these properties on immutable offline mounts. It is not a production sandbox or a proof against concurrent parent-directory replacement.

Use one transactional active generation per partition. Build the next generation separately, verify it, then switch the pointer. Delete and rename events remove old entries from the next generation. Recheck source bytes before citations. A stale generation must fail closed for citation reads. Report reasons such as `STALE_FILE`, `PARTITION_MISMATCH`, `PATH_REJECTED`, `RANGE_INVALID` and `MODEL_UNAVAILABLE` through bounded local metrics.

For Git, retain the exact object identity and manifest digest. For Gitless input, use a versioned snapshot identity from normalized sorted file metadata and hashes. Do not manufacture a commit SHA. Bind factory context contracts to a tagged Git-or-snapshot identity in a later compatible contract change.

## Bounded future implementation plan

1. Define and test the manifest, result and trusted-read contracts. Cover partitions, deletion, rename, stale source, symlinks, range forgery and cache identity. Keep the existing graph API unchanged.
2. Add an opt-in local lexical and exact-symbol reader over an explicit approved manifest. Reuse project services for source selection. Keep model files and indexes out of Git and managed payloads.
3. Add the pinned local model behind an optional adapter. Require verified model bytes, fixed tokenizer settings and a resource budget. Keep all inference offline by default. Do not add a remote embedding provider in this step.
4. Add transactional index generation and rollback to the last verified generation. Use existing cache lifecycle patterns. Rebuild after schema or model changes. Surface completeness and rejected-source counts.
5. Expand the judged set with independent repositories, languages, tasks and blind labels. Measure downstream answer citation coverage separately. Revisit weights only in a new preregistered experiment. This experiment cannot justify a global weight or model choice.
6. Add optional RRF after contract and evaluation checks. Expose component evidence and context costs. Run route-selected review and normal repository gates for the actual product diff.

Roll out with an explicit local command and a feature flag off by default. Observe index counts, incomplete files, query latency, model load failures and stale citation rejections. Roll back by disabling ranked retrieval and removing only its owned cache generation. Preserve source files, the graph cache and prior valid generations. No daemon, service, database migration, production write or external source upload is required by this design.
