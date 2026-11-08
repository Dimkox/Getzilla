from __future__ import annotations

import signal
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.state import get_agent_state, record_agent_start, record_agent_stop
from tests._support import activate_owned_route
from tests._support import project_copy, run_hook

T0 = datetime(2030, 1, 1, tzinfo=timezone.utc)


class AgentLifecycleVerificationTests(unittest.TestCase):
    def test_tool_receipt_invalidation_and_verifier_cancel_preserve_writer_progress(self) -> None:
        from getzilla import verification as verifier
        from getzilla.agent_lifecycle import update_agent
        from getzilla.python_test_runner import RunCancelled
        from getzilla.receipts import get_receipt, write_receipt
        with project_copy(git=True) as root:
            self.start(root)
            record_agent_stop(root, 'writer-1', 'general_implementer', now=T0)
            record = record_agent_start(root, 'writer-1', 'general_implementer')
            payload = {'cwd': str(root), 'session_id': 'fixture-owner', 'tool_name': 'Read', 'agent_id': 'writer-1',
                       'agent_type': 'general_implementer',
                       'generation': record['generation']}
            self.assertEqual(run_hook(root, 'post_tool_use.py', payload)[0], 0)
            write_receipt(root, 'verification', 'pass')
            (root / 'source.py').write_text('source changed\n')
            self.assertEqual(run_hook(root, 'post_tool_use.py', payload)[0], 0)
            invalidated = get_receipt(root, 'route-229', 'verification')
            self.assertTrue(invalidated['stale'])
            self.assertEqual(invalidated['status'], 'pass')
            active = get_agent_state(root)['active']['writer-1']
            self.assertEqual(active['last_progress_at'], record['last_progress_at'])
            update_agent(root, 'writer-1', record['generation'], 'route-229', 'task-229',
                         'progress', checkpoint='implementation')
            before = get_agent_state(root)
            with patch.object(verifier, '_python', side_effect=RunCancelled(signal.SIGTERM)), \
                 patch.object(verifier, '_semgrep', return_value=None), \
                 patch.object(verifier, '_trivy_config', return_value=None):
                with self.assertRaises(verifier.VerificationCancelled):
                    verifier.verify(root, mode='fast', record=False)
            self.assertEqual(get_agent_state(root), before)
            with self.assertRaises(ValueError):
                record_agent_start(root, 'writer-2', 'general_implementer')
            self.assertEqual(run_hook(root, 'subagent_stop.py', payload)[1], {})
            self.assertNotIn('writer-1', get_agent_state(root)['active'])


    def start(self, root: Path) -> dict:
        activate_owned_route(root, {'route_id': 'route-229', 'change_id': 'task-229',
                                'write_agent': 'general_implementer',
                                'allowed_agents': ['general_implementer', 'repo_explorer']})
        return record_agent_start(root, 'writer-1', 'general_implementer', now=T0)
