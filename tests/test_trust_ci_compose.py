"""Trust CI compose: the runner-loader script is expanded by the container shell, never by Compose."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / 'trust-ci' / 'compose.yaml'
# Compose's own interpolation grammar: `$$` is a literal `$`; anything else after `$` is interpolated by Compose.
DOLLAR = re.compile(r'\$(\$|\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|)')
CONTAINER_VAR = re.compile(r'\$\$(?:\{([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*))')


def block(text: str, header: str, indent: int) -> str:
    """Lines nested under `header` at `indent` spaces; fails closed when the header is missing or duplicated."""
    pattern = rf'^{" " * indent}{re.escape(header)}:\n((?:(?:{" " * (indent + 2)}.*)?\n)*)'
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise AssertionError(f'expected one {header!r} at indent {indent} in {COMPOSE}, found {len(matches)}')
    return matches[0]


def compose_interpolated(script: str) -> list[str]:
    """Every `$` token Compose would interpolate (or swallow) instead of passing to the container."""
    return [match.group(0) for match in DOLLAR.finditer(script) if match.group(1) != '$']


class RunnerLoaderComposeTests(unittest.TestCase):
    def setUp(self) -> None:
        loader = block(COMPOSE.read_text(encoding='utf-8'), 'runner-loader', 2)
        self.script = block(loader, 'command', 4)
        self.environment = block(loader, 'environment', 4)

    def test_detector_flags_compose_interpolation_and_accepts_escapes(self) -> None:
        script = 'test "$resolved" = "$$TRUST_CI_RUNNER_IMAGE" ${X:?} $(date) $$$y $${z}'
        self.assertEqual(compose_interpolated(script), ['$resolved', '${X:?}', '$', '$y'])

    def test_runner_loader_script_has_no_compose_interpolation(self) -> None:
        self.assertEqual(compose_interpolated(self.script), [],
                         'runner-loader command must escape every shell $ as $$ (Compose blanks unset names)')

    def test_runner_loader_script_variables_are_defined_in_the_container(self) -> None:
        provided = set(re.findall(r'^      ([A-Za-z_][A-Za-z0-9_]*):', self.environment, re.MULTILINE))
        assigned = set(re.findall(r'^\s*([A-Za-z_][A-Za-z0-9_]*)=', self.script, re.MULTILINE))
        used = {braced or bare for braced, bare in CONTAINER_VAR.findall(self.script)}
        self.assertEqual({'TRUST_CI_RUNNER_IMAGE', 'resolved'}, used)
        self.assertEqual(used - provided - assigned, set())
        self.assertRegex(self.environment, r'TRUST_CI_RUNNER_IMAGE: \$\{TRUST_CI_RUNNER_IMAGE:\?')

    def test_runner_loader_still_requires_the_exact_pinned_digest(self) -> None:
        self.assertIn('test "$$resolved" = "$$TRUST_CI_RUNNER_IMAGE"', self.script)


if __name__ == '__main__':
    unittest.main()
