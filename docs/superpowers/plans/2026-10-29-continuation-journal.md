# Offline Continuation Journal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Preserve attempt and request budgets across crashes without enabling dispatch.

**Architecture:** One bounded journal uses pinned descriptors, a stable kernel lock and file plus directory fsync. Each task retains original usage and immutable caps. No production adapter is qualified.

**Tech Stack:** Python standard library and existing fsx/policy APIs.

**Spec:** Issue235 T3; docs/model-continuation.md and independent T3 runtime/code-impact analyses.

## Constraints and review focus

No provider, hook, credential, Factory or progress-recovery changes. Candidate zero is the original attempt. Monetary caps round down and charges up. Missing/corrupt state, stale callbacks, revocation, directory substitution, crashes and backward clocks must fail closed. Journal state never proves fencing or grants tool authority.

## Tasks

- [x] Observe RED policy-money and offline journal fixtures.
- [x] Implement exact monetary parsing and bounded durable state.
- [x] Test concurrency, crash boundaries, restart, original budgets, cancellation, unsafe files and no adapter.
- [ ] Document limits; run focused controls, commit and reconcile. Coordinator owns final gate.

## Rollback

Keep continuation unavailable. Revert source through a reviewed PR while preserving journals and unresolved attempts.

Execution: 29 focused tests passed, including18journal tests and11existing policy/startup fixtures. RED regressions caught float-rounded policy caps, revocation during the private admission boundary and malformed event types. Independent spawned processes reserved once; pre/post-publication failure and filesystem refusal fixtures passed. The private test boundary does not qualify production adapters.
