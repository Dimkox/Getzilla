# Inactive security checker bootstrap

This checkout contains an optional scanner library and CLI. It supplies checker
source bytes. It does not activate a workflow, admission check, GitHub App,
protection rule, deployed producer or trusted checker pin.

Run `python3 scripts/getzilla_security.py --help` to inspect the CLI. The checker
requires Python 3.11 or newer. Structural YAML inventory requires PyYAML; missing
capability remains a coverage gap. Acquisition needs explicit `--refresh`.
Importing the checker performs no network access or process execution.

`security_osv_snapshot.py` owns the strict snapshot contract used by the new
checker. It requires bounded validated inputs and acquisition evidence no older
than 72 hours. Malformed, stale, partial and substituted sources fail closed.
A failed refresh preserves the previous snapshot pointer and acquisition time.
Legacy `known_vulns.py`, `updater.py`, `scripts/getzilla_vulns.py` and their existing
consumers retain their current behavior. Their migration remains separate work.

Artifact evidence distinguishes exact source, digest, platform/ABI and use/output
context. Extracted Factory output needs its actual archive, detached identity,
complete source-wheel composition and retained license/notice members. The six
approved licenses remain unchanged. The copied policy's approved Factory pins
differ from main's inputs; this remains `license-factory-profile-changed`.
Synthetic positive controls do not reanchor that project decision or establish
acceptance of the current real release. Tools, Actions, images and unresolved
source/output contexts retain their explicit gaps.

Local synthetic tests qualify source and refusal behavior only. They do not
establish successful live feed acquisition, legal approval, independent runner
qualification or complete Getzilla security acceptance. Choosing the reviewed
checker pin, deploying the independent producer/App, binding protection and
qualifying final merge-time admission remain owner steps. Required full local
verification, independent reviews and exact-head external checks still apply.
