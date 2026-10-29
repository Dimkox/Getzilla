# Model Continuation Startup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Load a strict shared policy and report truthful startup capability for six harnesses without dispatching requests.

**Architecture:** A pure shared module validates bounded non-secret configuration and classifies normalized model failures. The canonical startup hook and existing status CLI expose passive status. All adapters remain unqualified.

**Tech Stack:** Python standard library, unittest, existing harness generator.

**Spec:** [Issue 235](https://github.com/Dimkox/Getzilla/issues/235), first slice T2/T6a (FR-001–003, FR-011–012).

## Global Constraints

- No provider requests, credential discovery, native-default changes or automatic dispatch.
- Eligible failure classification is not permission to dispatch.
- T3/T4/T5/T6b and actual adapter qualification remain in issue 235.
- One writer; independent review and exact-source verification follow the commit.

## Review Focus

- Malformed, oversized, duplicate-key and nonregular policy inputs fail closed with safe reason codes.
- Unknown fields, boolean numbers and nonfinite budgets fail closed.
- Model-origin classification cannot make tool, test, safety or cancellation errors eligible.
- Native startup output visibility differs by harness; generated wiring is not qualification.
- Installed config updates use existing AGBP_SYNC kept_local/digest preservation; never imply automatic retention.

## Task 1: Strict passive contract

Files: `.getzilla/getzilla/model_continuation.py`, `.getzilla/config/model-continuation.json`, `tests/test_model_continuation.py`.

- [x] Write failing fixtures for bounded policy loading, ordered candidates, finite bounds, sanitized status, and every failure-table category.
- [x] Observe RED with the focused test module.
- [x] Implement `load_policy(root)`, `classify_failure(event)`, and `startup_status(root, harness)` with immutable policy values and no external effects.
- [x] Run fixtures; require GREEN.

## Task 2: Startup and status integration

Files: `.grok/hooks/session_start.py`, generated harness mirrors, `scripts/getzilla_status.py`, focused tests and README.

- [x] Add failing six-harness startup fixtures, no-route coverage and installed-payload checks in a private fixture.
- [x] Append one safe status note using `_lib.harness()`; add CLI `getzilla status --harness NAME`.
- [x] Regenerate canonical harness outputs and test payloads without claiming native visibility for unsupported channels.
- [x] Document configuration, preservation and partial capability.
- [ ] Run bounded controls, commit, reconcile route and hand off for independent review.

Execution evidence: 80 focused tests and 206 subtests passed in a private source snapshot with eight workers. Ruff and harness generation passed. Copilot's documented top-level context required a RED/GREEN envelope fixture. Existing OpenRouter `:free` IDs required separate model identifier validation; the compatibility regression passed. Runtime client qualification remains unverified.

## Rollback

Keep `enabled:false` to request no continuation. This slice never dispatches. Revert this candidate through a reviewed PR to remove passive reporting; preserve any consumer policy override.
