"""Missing native delivery cannot be replaced by local report observations."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


class ExperimentEvidenceTests(unittest.TestCase):
    def test_unbound_native_publication_never_issues_refs(self):
        from getzilla.retrieval import experiment_evidence as evidence
        for cls in (evidence.ReviewedInputsRef, evidence.PhaseARef, evidence.PhaseBRef):
            with self.assertRaises(TypeError):
                cls()
        for claim in (None, {}, {'reviewer': 'independent', 'phase_a': True},
                      {'qualification': 'local-observation-only', 'result': 'completed', 'dataset_sha256': 'a' * 64}):
            with self.assertRaisesRegex(ValueError, 'native_publication_unbound'):
                evidence.verify_phase_a(claim)
            with self.assertRaisesRegex(ValueError, 'native_publication_unbound'):
                evidence.verify_phase_b(claim)

    def test_default_status_and_execution_touch_no_research_inputs(self):
        code = """import runpy,sys
script=sys.argv[1]
def audit(event,args):
 if event in ('socket.connect','subprocess.Popen','os.system'):
  raise RuntimeError('disabled status attempted effect')
 if event=='import' and args[0].split('.')[0] in {'onnxruntime','onnx','numpy','tokenizers','torch','transformers'}:
  raise RuntimeError('disabled status imported model runtime')
sys.addaudithook(audit)
sys.argv=[script,'status']
runpy.run_path(script,run_name='__main__')
"""
        result = subprocess.run([sys.executable, '-I', '-c', code,
                                 str(ROOT / 'scripts/getzilla_retrieval_experiment.py')],
                                cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('native_publication_unbound', result.stdout)
        self.assertIn('"ranking_permitted": false', result.stdout)
        self.assertNotIn('onnxruntime', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
