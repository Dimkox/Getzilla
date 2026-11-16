"""Closed filesystem controls for the interrupt fixture's readiness record."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def publish_owned_group(destination: Path | str, pid: int, group: int) -> None:
    """Publish readiness only after this private fixture's record is closed."""
    destination = Path(destination)
    temporary = destination.with_name(destination.name + '.publishing')
    with temporary.open('x', encoding='ascii') as output:
        json.dump([pid, group], output)
    temporary.replace(destination)


class OwnedGroupPublicationTests(unittest.TestCase):
    def test_readiness_exposes_only_a_complete_record_and_write_failure_refuses(self):
        publish = globals().get('publish_owned_group')
        self.assertTrue(callable(publish), 'complete record publication helper is absent')
        for interrupted in (False, True):
            with self.subTest(interrupted=interrupted), tempfile.TemporaryDirectory(
                    prefix='new-pid-publication-', dir=ROOT / '.getzilla/runtime') as raw:
                final = Path(raw) / 'ready.json'
                observed = []
                def partial_write(value, output):
                    output.write('[')
                    output.flush()
                    observed.append(final.exists())
                    if interrupted:
                        raise OSError('new closed fixture write interruption')
                    output.write(json.dumps(value)[1:])
                with patch.object(json, 'dump', side_effect=partial_write):
                    if interrupted:
                        with self.assertRaises(OSError):
                            publish(final, 123, 456)
                    else:
                        publish(final, 123, 456)
                self.assertEqual(observed, [False], 'partial output became a readiness record')
                if interrupted:
                    self.assertFalse(final.exists(), 'failed publication appeared ready')
                else:
                    self.assertEqual(json.loads(final.read_text()), [123, 456])
        # Tie the new helper to the retained producer without executing its body.
        tree = ast.parse((ROOT / 'tests/test_parallel.py').read_bytes())
        method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
            and node.name == 'test_main_thread_interrupt_stops_owned_group_before_returning')
        producer = next(node.value for node in method.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == 'producer'
                                for target in node.targets))
        literals = ''.join(node.value for node in ast.walk(producer)
                           if isinstance(node, ast.Constant) and isinstance(node.value, str))
        self.assertIn('from tests.test_parallel_fixture_publication import publish_owned_group;', literals)
        self.assertIn('publish_owned_group(', literals)


if __name__ == '__main__':
    unittest.main()
