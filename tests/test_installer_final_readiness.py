"""Exercise the actual shell bootstrap join with owned inert component effects."""
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class InstallerFinalReadinessTests(unittest.TestCase):
    def test_pending_provider_does_not_print_ready_and_final_doctor_uses_venv(self):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='installer-readiness-', dir=scratch) as owned:
            home = Path(owned)
            (home / '.venv/bin').mkdir(parents=True)
            python = home / '.venv/bin/python'
            python.write_text('#!/bin/bash\nprintf "managed-python:%s\\n" "$*"\nexit 0\n')
            python.chmod(0o755)
            source = (ROOT / 'scripts/install.sh').read_text().rsplit('main "$@"', 1)[0]
            harness = home / 'join.sh'
            harness.write_text(source + '''
ensure_git_and_python() { :; }
find_python() { printf '%s/.venv/bin/python' "$GETZILLA_HOME"; }
choose_agent() { echo qwen; }
choose_provider() { echo openrouter; }
choose_eu_ai_act() { :; }
install_agent() { :; }
fetch_getzilla() { :; }
link_getzilla_command() { :; }
setup_python_env() { :; }
configure_agent() { echo 'provider incomplete'; return 3; }
update_security_data() { echo security-updated; }
install_workflow_baseline() { echo baseline-updated; }
git() { echo 'git version 2.50.0'; }
main
''')
            result = subprocess.run(['bash', str(harness)], env=dict(PATH='/usr/bin:/bin', HOME=str(home),
                                    GETZILLA_HOME=str(home), GETZILLA_NONINTERACTIVE='1'),
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('Getzilla is ready', result.stdout)
            self.assertIn('baseline-updated', result.stdout)
            self.assertIn('managed-python:scripts/getzilla_doctor.py', result.stdout)
            self.assertLess(result.stdout.index('baseline-updated'),
                            result.stdout.index('managed-python:scripts/getzilla_doctor.py'))
