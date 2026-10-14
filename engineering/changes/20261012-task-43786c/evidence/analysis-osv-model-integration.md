# OSV model integration analysis

No blocking semantic mismatch found in the dirty scanner model diff. Analysis only; not an independent PASS review or gate.

Source: canonical runtime worktree fix-codex-cmd-20261011, HEAD8c candidate with writer-owned architecture/system.yaml changes. Read-only source inspection. No network requests or source mutations.

Commands: git diff -- architecture/system.yaml; rg -n network caller/timeout/online/offline patterns in .getzilla/getzilla/known_vulns.py; sed -n 373,418p and 445,510p of that module; read scripts/getzilla_vulns.py. Commands exited0.

- Scanner query edge covers POST https://api.osv.dev/v1/querybatch with package name, ecosystem, version and optional page_token. Detail GET uses /vulns/<advisory-id>. No source code, manifest file contents, credentials or secrets are transmitted by these callers.
- Archive edge covers GET https://osv-vulnerabilities.storage.googleapis.com/<supported-ecosystem>/all.zip. Downloads validate ZIP CRC before replacing the local mirror. This is a local filesystem update, not a remote publication or mutation.
- Both callers use urllib timeout60 seconds per request, no automatic error retries or authentication. Model timeout_ms60000/max_retries0/authentication none match. Pagination may send multiple requests; 60 seconds is not a whole-scan deadline.
- Online scan requires --online or GETZILLA_OSV_ONLINE=1. An explicit offline DB takes priority and does not call these network paths. With no pins or no source selection the scanner reports skip, not pass. Explicit --download-db is a separate network operation. Edge fail_closed applies to attempted network calls, not default skipped scanning.
- Endpoint and data roles match the narrow scanner node. Existing no-network hook/runner declarations need no expansion.

Limitation: allowlisted_egress states architectural endpoint intent. Source uses fixed initial HTTPS hosts but default urllib redirect handling; this is not an OS-enforced host allowlist or proof of deployed egress enforcement. Do not claim otherwise. No deployment/network runtime evidence was collected.

Root and writer received findings before report completion. No behavioral repair requested. Full independent reviews and fresh final gate must follow the completed source/model tree.

reviewed-tree-modified: no
