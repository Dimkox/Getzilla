# Optional completed-install analytics

Status: repository primitives implemented. Production hosting, vendor delivery and observed conversion/attribution are **NOT_TESTED**. This change does not activate an endpoint or add a service. Do not treat backend HTTP acceptance as a conversion.

The shell and PowerShell installers call the optional helper only after all mandatory stages, current managed-software verification, doctor exit 0 and agent/provider setup exit 0. Doctor warnings that still return 0 are compatible with readiness. Project setup and first-task activation remain separate. Any failed stage stops before notification.

## Client consent and privacy

Default installations make no analytics request. To opt in, set all three variables explicitly:

- `GETZILLA_INSTALL_ANALYTICS=1`
- `GETZILLA_INSTALL_ANALYTICS_ENDPOINT=https://getzilla.app/api/install-complete`
- `GETZILLA_INSTALL_TOKEN`: the unchanged opaque server-issued token.

Keep the release scripts and their pinned-download/SHA-256 checks identical for every user. Pass the token in the environment; never render it into script bytes. Disable with `GETZILLA_INSTALL_ANALYTICS=0` or remove any required variable. CI, GitHub Actions, Azure builds, `GETZILLA_INTERNAL_RUN` and `GETZILLA_SMOKE_TEST` suppress events. Set the internal flag for every internal validation run. A caller can lie about these flags; the host must also exclude internal token issuance.

The fixed HTTPS endpoint has no redirect or ambient proxy support. The parent process kills the transport after four seconds, including DNS/TLS delay. A request has a two-second socket timeout. There is no resident process or retry loop. The client retries on at most three eligible installer runs within 72 hours. An outage cannot fail installation. The payload contains only token, random stable event identity, canonical event name, installed version, OS and actual first successful readiness time. It contains no keys, username, local path, source code or environment dump.

State lives in `GETZILLA_STATE_HOME/install-analytics` (default `~/.getzilla/install-analytics`). Reruns and upgrades reuse the identity and original event time. A successful backend response suppresses future requests. A clean source reinstall keeps this state. Deleting/resetting the state creates a new installation identity and can count again. Installation count is not unique-person count. Concurrent runs use an exclusive directory lock. A killed process can leave this lock; that suppresses later telemetry until the owner removes the stale lock. Prefer an undercount to an unbounded or duplicate retry.

## Optional host integration

`.getzilla/getzilla/install_analytics.py` exposes framework-neutral `Store`, `collect` and `vendor_jobs`. No server is started. No vendor API is called. No account or credential is required to install Getzilla.

Before exposing the fixed route, the host owner must supply and verify:

1. HTTPS ownership for the exact endpoint; POST only; JSON content type; body limit 2 KiB before parsing; trusted request clock; bounded per-origin/token rates; no request body/token logging; private durable SQLite location, retention and access policy.
2. Website analytics consent capture, revocation and server-side internal-run exclusion. Issue a random 256-bit token only after explicit applicable consent. Store only approved actual browser identifier strings and allowlisted acquisition fields. Never accept caller-supplied source URLs or arbitrary fields. Avoid personal data in UTM fields. Set a 24-hour token TTL scoped to this event. Revocation calls `Store.revoke`; the host must stop outstanding delivery jobs too.
3. Real GA4 `client_id`/`session_id`, Metrika `ClientID`, browser session start and verified session end where available. Unknown session end must remain unknown. `Store.issue` returns the opaque token; only its digest persists. No-token/generic commands send nothing. Missing identifiers do not block installation or backend acceptance; the relevant vendor job is omitted. No IP matching or invented attribution occurs.
4. An HTTP adapter that validates through `collect` and returns 202 for both newly accepted and duplicate valid requests. SQLite's primary key suppresses repeats across tokens, processes, reruns and upgrades. Retain the first source and actual event time. Expired, revoked, malformed and invalid tokens fail closed. Store-side dedup does not guarantee exactly-once vendor delivery.
5. Server-owned delivery adapters and bounded queues. `vendor_jobs` prepares data only. Resolve `server:ga4-api-secret` and `server:metrika-oauth` through the existing host secret system. Never send references or secrets to clients or read secrets during repository verification. Configure fixed Google/Yandex endpoints and approved property/stream/counter IDs on the host. Recompute eligibility at send time. Use a lease/atomic delivery claim, do not auto-retry an ambiguous vendor response, and persist upload IDs and failures through `Store.delivery`. Backend acceptance, vendor acceptance, processing and observed attribution are separate fields. Initial processing and attribution are unknown.

## Vendor setup and timing

Register `getzilla_install_complete` as a GA4 key event in the existing Web stream. The prepared Measurement Protocol body uses actual event `timestamp_micros` and real browser `client_id`; it never synthesizes one. Include the original session ID only when receipt is within 24 hours of session start and the actual timestamp lies inside that session. Missing/late session linkage remains unknown. Suppress events older than 72 hours rather than clamping their timestamp. Configure validation and inspect test-property reports; HTTP success alone does not prove a valid processed event.

Create a Metrika JavaScript/target-event goal with exact-match identifier `getzilla_install_complete`. Upload CSV columns `ClientId,Target,DateTime` through offline conversions only. Do not also use Metrika Measurement Protocol. Use the original Unix event time. ClientID links to the eligible preceding visit, which can differ from acquisition. The 21-day enrichment window runs from the visit through file processing. The prepared job uses captured visit time as a conservative deadline; missing visit time suppresses upload. The host must leave processing margin, poll the upload ID and record actual processing/matching. Later unknown visits cannot justify fabricated attribution.

Primary contracts checked on 2026-11-19:

- [GA4 sending events and 72-hour timestamps](https://developers.google.com/analytics/devguides/collection/protocol/ga4/sending-events)
- [GA4 session-attribution requirements](https://developers.google.com/analytics/devguides/collection/protocol/ga4/use-cases)
- [GA4 key-event setup](https://support.google.com/analytics/answer/13128484?hl=en)
- [Metrika offline columns, goal and upload](https://yandex.ru/dev/metrika/ru/management/offline-conv)
- [Metrika visit matching and 21-day processing window](https://yandex.ru/support/metrica/ru/data/offline-params)

## Verification

Run `taskset -c 2 python3 -m unittest discover -s tests -p test_install_analytics.py`. The tests use local temporary SQLite state and stub transport. Bash executes a stubbed installer flow. PowerShell executes the actual final-readiness segment with stubbed tools, if `pwsh` is available. This is not a Windows installation test.

Before rollout, use an approved test property/counter and test host. Verify consented browser-to-other-host token handoff, real processed GA4 key event, Metrika upload status and goal, source linkage inside each platform window, late/unmatched behavior, revocation, duplicate suppression and host queue/retry/rate controls. Record exact IDs/times and report evidence without tokens or secrets. These host checks, native Windows/macOS installation, live website token issuance and vendor observations remain **NOT_TESTED**. No production marketing event is authorized by these offline tests.
