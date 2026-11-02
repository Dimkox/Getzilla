#!/usr/bin/env python3
"""Bounded root continuation and independent verification-claim checks."""
from __future__ import annotations

import sys
from pathlib import Path

for _p in (Path.cwd(), Path.cwd() / ".getzilla"):
    s = str(_p)
    if s not in sys.path:
        sys.path.append(s)

try:
    from _lib import emit, harness, read_payload, record_degraded, root_from, stop_hook_active
except Exception:
    print('{}')
    raise SystemExit(0)


def main() -> None:
    try:
        payload = read_payload()
        root = root_from(payload)
        try:
            from getzilla.package_status import collect_worktree, diagnostic_messages, inspect_package, receipt_inputs_unavailable
            from getzilla.receipts import validate_evidence
            from getzilla.state import current_session, get_active_change, get_active_route, increment_stop_attempt, reset_stop_attempt
            from getzilla.completion import STOP_ATTEMPT_LIMIT, continuation_reason, is_root_stop, observe_remaining
        except Exception:
            emit({})
            return

        route = get_active_route(root)
        if not is_root_stop(payload, current_session()):
            emit({})
            return
        owned = bool(route and current_session() and current_session() == route.get('session_id'))
        from getzilla.continuity import TERMINAL
        if route and route.get('status') in TERMINAL:
            emit({})
            return
        if route:
            try:
                from getzilla.claim_check import BLOCKING_HARNESSES, stop_mode, unsupported_claim
                from getzilla.hook_health import route_degraded_events

                claim = unsupported_claim(root, route, payload)
                degraded = route_degraded_events(root, route)
            except Exception as error:  # noqa: BLE001 - the checks are advisory; record that they did not run
                record_degraded('stop_gate', error, payload)
                claim, degraded = None, []
            if owned and claim and stop_mode(root, route) == 'strict' and not stop_hook_active(payload):
                if harness() in BLOCKING_HARNESSES:
                    emit({'decision': 'block', 'reason': continuation_reason([claim])})
                    return
                record_degraded('stop_gate', f'STRICT_BLOCK_UNSUPPORTED:{harness()}', payload)
        else:
            claim, degraded = None, []
        messages = []
        unsafe_inputs = False
        package = None
        try:
            active = get_active_change(root)
        except (ValueError, OSError):
            active = None
            unsafe_inputs = True
            messages.append('selected package authority unavailable; scope synchronization is blocked')
        if not route:
            from getzilla.continuity import unavailable_authority_notice
            notice = unavailable_authority_notice(root)
            if notice:
                messages.append(notice)
        if active:
            package = inspect_package(root, route, active)
            worktree = collect_worktree(root, route, package['initial_checkpoint'])
            messages = diagnostic_messages(package, worktree)
            unsafe_inputs = receipt_inputs_unavailable(package)
        if not route:
            emit({'systemMessage': 'Adaptive note (non-blocking): ' + '; '.join(messages)} if messages else {})
            return
        gaps = (
            ['package: receipt validation unavailable until unsafe or unreadable selected inputs are resolved']
            if unsafe_inputs else validate_evidence(root, route) if route.get('required_evidence') else []
        )
        from getzilla.continuity import scope_gaps
        scope = scope_gaps(root, route)
        observation = observe_remaining(route, package, scope, gaps, unsafe=unsafe_inputs)
        remaining = observation['remaining']
        if owned and remaining:
            summary = 'unfinished task: ' + '; '.join(remaining)[:3000]
            if observation['blocked_reason']:
                messages.insert(0, 'task paused: ' + observation['blocked_reason'] + '; ' + summary)
            elif harness() not in BLOCKING_HARNESSES:
                messages.insert(0, summary + '; automatic Stop continuation is unsupported by this harness')
            elif stop_hook_active(payload):
                messages.insert(0, summary + '; native continuation already used; task remains open')
            else:
                try:
                    attempt = increment_stop_attempt(root, route['route_id'], observation=observation['fingerprint'])
                except (ValueError, OSError) as error:
                    messages.insert(0, summary + '; retry state unavailable: ' + str(error)[:300])
                else:
                    if attempt <= STOP_ATTEMPT_LIMIT:
                        emit({'decision': 'block', 'reason': continuation_reason(remaining)})
                        return
                    messages.insert(0, summary + '; unchanged-work continuation limit reached; task remains open')
        gaps = [*scope, *gaps]
        if gaps:
            messages.insert(0, 'missing/stale evidence: ' + '; '.join(gaps))
        if claim:
            messages.insert(0, 'unsupported verification claim: ' + claim)
        if degraded:
            messages.append(f'{len(degraded)} hook call(s) failed open since this route started, so Getzilla policy '
                            'did not run for them (.getzilla/runtime/hook-events.jsonl)')
        if messages:
            emit({'systemMessage': 'Adaptive note (non-blocking): ' + '; '.join(messages)})
            return
        if not route.get('required_evidence'):
            emit({})
            return

        if owned:
            reset_stop_attempt(root, route['route_id'])
        emit({})
    except Exception as error:
        record_degraded('stop_gate', error)
        emit({})


if __name__ == '__main__':
    main()
