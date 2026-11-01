"""E03: 'tests pass' without a current verification receipt is flagged at stop; strict mode blocks where it can."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.claim_check import claims_verification, last_assistant_text  # noqa: E402
from getzilla.hook_health import degraded_events  # noqa: E402
from getzilla.receipts import write_receipt  # noqa: E402
from getzilla.router import build_route  # noqa: E402
from tests._support import activate_owned_route
from tests._support import project_copy  # noqa: E402


def transcript(path: Path, text: str) -> Path:
    lines = [{'type': 'user', 'message': {'role': 'user', 'content': 'сделай'}},
             {'type': 'assistant', 'message': {'role': 'assistant', 'content': [{'type': 'text', 'text': text}]}}]
    path.write_text('\n'.join(json.dumps(line, ensure_ascii=False) for line in lines) + '\n', encoding='utf-8')
    return path


def stop(root: Path, payload: dict, harness: str = 'claude', mode: str | None = None) -> dict:
    env = {key: value for key, value in os.environ.items() if key != 'GETZILLA_STOP_GATE_MODE'}
    if mode:
        env['GETZILLA_STOP_GATE_MODE'] = mode
    proc = subprocess.run([sys.executable, str(root / '.grok/hooks/stop_gate.py'), '--harness', harness], cwd=root,
                          input=json.dumps({'cwd': str(root), 'stop_hook_active': False, **payload}).encode('utf-8'),
                          capture_output=True, check=False, env=env)
    return json.loads(proc.stdout.decode('utf-8').strip() or '{}')


class ClaimDetectionTests(unittest.TestCase):
    def test_claims_in_english_and_russian(self) -> None:
        for text in ('All tests pass.', 'Tests passed, ready to merge', 'CI is green', 'Все тесты прошли',
                     'тесты зелёные, можно мержить', 'Проверки прошли успешно'):
            with self.subTest(text=text):
                self.assertTrue(claims_verification(text))
        for text in ('I added a test for the parser', 'Тесты ещё не запускал', 'The build failed'):
            with self.subTest(text=text):
                self.assertFalse(claims_verification(text))

    def test_last_message_from_payload_or_transcript(self) -> None:
        self.assertEqual(last_assistant_text({'last_assistant_message': 'done, tests pass'}), 'done, tests pass')
        with tempfile.TemporaryDirectory() as tmp:
            path = transcript(Path(tmp) / 't.jsonl', 'Готово, все тесты прошли')
            self.assertEqual(last_assistant_text({'transcript_path': str(path)}), 'Готово, все тесты прошли')
        self.assertIsNone(last_assistant_text({'transcript_path': '/no/such/file'}))


class StopGateClaimTests(unittest.TestCase):
    def prepare(self, root: Path, claim: str = 'Готово, все тесты прошли') -> dict:
        activate_owned_route(root, build_route(root, 'Добавить функцию', 's1').to_dict())
        (root / 'feature.txt').write_text('changed', encoding='utf-8')
        return {'transcript_path': str(transcript(root / '.getzilla' / 'runtime' / 't.jsonl', claim))}

    def test_soft_mode_warns_about_unsupported_claim(self) -> None:
        with project_copy(git=True) as root:
            data = stop(root, self.prepare(root))
            self.assertNotEqual(data.get('decision'), 'block')
            self.assertIn('unsupported verification claim', str(data.get('systemMessage')))

    def test_strict_mode_blocks_on_claude_and_codex(self) -> None:
        with project_copy(git=True) as root:
            payload = self.prepare(root)
            for harness in ('claude', 'codex'):
                with self.subTest(harness=harness):
                    data = stop(root, payload, harness, 'strict')
                    self.assertEqual(data.get('decision'), 'block')
                    self.assertIn('no passing verification receipt', data.get('reason', ''))
            again = stop(root, {**payload, 'stop_hook_active': True}, 'claude', 'strict')
            self.assertNotEqual(again.get('decision'), 'block')

    def test_strict_on_agent_without_blocking_degrades_to_warning(self) -> None:
        with project_copy(git=True) as root:
            data = stop(root, self.prepare(root), 'qwen', 'strict')
            self.assertNotEqual(data.get('decision'), 'block')
            self.assertIn('unsupported verification claim', str(data.get('systemMessage')))
            self.assertTrue(any('STRICT_BLOCK_UNSUPPORTED:qwen' in event['error'] for event in degraded_events(root)))

    def test_current_receipt_or_no_claim_is_quiet(self) -> None:
        with project_copy(git=True) as root:
            payload = self.prepare(root)
            write_receipt(root, 'verification', 'pass')
            data = stop(root, payload, 'claude', 'strict')
            self.assertNotEqual(data.get('decision'), 'block')
            self.assertNotIn('unsupported verification claim', str(data.get('systemMessage')))
        with project_copy(git=True) as root:
            data = stop(root, self.prepare(root, 'Я поправил парсер, тесты ещё не запускал'), 'claude', 'strict')
            self.assertNotIn('unsupported verification claim', str(data.get('systemMessage')))


if __name__ == '__main__':
    unittest.main()
