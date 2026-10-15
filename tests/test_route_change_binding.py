from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.router import build_route
from getzilla.state import (
    ActiveChangeConflict,
    get_active_route,
    set_active_change,
    set_active_route,
)
from getzilla.util import dump_json
from tests._support import project_copy, run_hook


def _route(route_id: str, session: str = 's1') -> dict:
    return {'route_id': route_id, 'session_id': session, 'task': 't', 'created_at': '2026-10-15T00:00:00+00:00'}


def _bind_change(root: Path, route_id: str, status: str = 'draft') -> None:
    rel = 'engineering/changes/20261015-task-' + route_id[:6]
    dump_json(root / rel / 'state.json', {'change_id': rel.rsplit('/', 1)[1], 'route_id': route_id, 'status': status})
    set_active_change(root, {'change_id': rel.rsplit('/', 1)[1], 'path': rel})


class RouteChangeBindingTests(unittest.TestCase):
    def test_open_change_pins_active_route(self) -> None:
        with project_copy() as root:
            set_active_route(root, _route('aaaaaaaaaaaa'))
            _bind_change(root, 'aaaaaaaaaaaa')
            with self.assertRaises(ActiveChangeConflict):
                set_active_route(root, _route('bbbbbbbbbbbb'))
            self.assertEqual(get_active_route(root)['route_id'], 'aaaaaaaaaaaa')
            self.assertFalse((root / '.getzilla/runtime/routes/bbbbbbbbbbbb.json').exists())

    def test_same_route_can_be_restored(self) -> None:
        with project_copy() as root:
            _bind_change(root, 'aaaaaaaaaaaa')
            set_active_route(root, _route('aaaaaaaaaaaa'))
            self.assertEqual(get_active_route(root)['route_id'], 'aaaaaaaaaaaa')

    def test_closed_change_releases_route(self) -> None:
        for status in ('cancelled', 'released', 'archived'):
            with self.subTest(status=status), project_copy() as root:
                set_active_route(root, _route('aaaaaaaaaaaa'))
                _bind_change(root, 'aaaaaaaaaaaa', status)
                set_active_route(root, _route('bbbbbbbbbbbb'))
                self.assertEqual(get_active_route(root)['route_id'], 'bbbbbbbbbbbb')

    def test_change_path_outside_changes_dir_is_ignored(self) -> None:
        with project_copy() as root:
            dump_json(root / 'elsewhere/state.json', {'route_id': 'aaaaaaaaaaaa', 'status': 'draft'})
            set_active_change(root, {'change_id': 'x', 'path': 'elsewhere'})
            set_active_route(root, _route('bbbbbbbbbbbb'))
            self.assertEqual(get_active_route(root)['route_id'], 'bbbbbbbbbbbb')

    def test_prompt_from_new_session_keeps_open_change_route(self) -> None:
        with project_copy(git=True) as root:
            original = build_route(root, 'Fix the hook root resolution bug', 'old').to_dict()
            set_active_route(root, original)
            _bind_change(root, original['route_id'])
            code, data, stderr = run_hook(root, 'user_prompt_submit.py', {
                'session_id': 'new-session',
                'cwd': str(root),
                'prompt': json.dumps({'task': 'Implement a new API endpoint with tests', 'phase': 'TDD_RED'}),
            })
            self.assertEqual(code, 0, stderr)
            self.assertEqual(get_active_route(root)['route_id'], original['route_id'])
            context = data['hookSpecificOutput']['additionalContext']
            self.assertIn('ADAPTIVE GROK ROUTE', context)
            self.assertIn('kept the active route', context)


if __name__ == '__main__':
    unittest.main()
