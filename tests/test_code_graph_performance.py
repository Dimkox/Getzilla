"""G10: generated 1000-file corpus; counters are asserted, duration and memory are only measured (no SLA)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.builder import build_generation  # noqa: E402
from getzilla.code_graph.impact import calculate_impact  # noqa: E402
from getzilla.code_graph.incremental import update_index  # noqa: E402
from getzilla.code_graph.store import GraphStore, build_full_index  # noqa: E402
from tests.code_graph_support import graph_input  # noqa: E402

COUNT = 1000


def corpus(count: int = COUNT) -> dict[str, str]:
    files = {'gen/__init__.py': ''}
    for index in range(count):
        group = index // 10 * 10
        partner = group + (index + 1) % 10  # 10-file import cycles
        lines = [f'from gen import m{partner}', f'from gen.m{max(index - 1, 0)} import f{max(index - 1, 0)}' if index else '']
        lines += [f'def f{index}(x):', f'    return f{max(index - 1, 0)}(x) if x else m{partner}.f{partner}(0)']
        if index % 97 == 0:
            lines += ['def dyn(name):', '    return getattr(m0, name)()']
        files[f'gen/m{index}.py'] = '\n'.join(line for line in lines if line) + '\n'
    return files


class GraphPerformanceTests(unittest.TestCase):
    def test_thousand_file_corpus_counters(self) -> None:
        files = corpus()
        tracemalloc.start()
        started = time.perf_counter()
        with tempfile.TemporaryDirectory() as tmp:
            store = GraphStore(Path(tmp) / 'graph.sqlite')
            try:
                full = build_full_index(graph_input(files), store)
                full_seconds = time.perf_counter() - started
                _, peak = tracemalloc.get_traced_memory()
                self.assertEqual(full.counters['parsed'], COUNT + 1)
                self.assertEqual(full.coverage.parsed_complete, COUNT + 1)
                leaf = dict(files)
                leaf['gen/m999.py'] = files['gen/m999.py'] + '# leaf edit\n'
                started = time.perf_counter()
                incremental = update_index(full, graph_input(leaf), store)
                incremental_seconds = time.perf_counter() - started
                self.assertEqual((incremental.counters['parsed'], incremental.counters['reused']), (1, COUNT))
                self.assertEqual(incremental.counters['resolved_files'], COUNT + 1)
                self.assertEqual(incremental.export(), build_generation(graph_input(leaf)).export())
                started = time.perf_counter()
                impact = calculate_impact(full, incremental, ['gen/m500.py'])
                impact_seconds = time.perf_counter() - started
                self.assertIn('gen/m501.py', impact.affected_files)
                self.assertIn('gen/m0.py', impact.affected_files)  # reached through the getattr gap files
            finally:
                store.close()
        tracemalloc.stop()
        measurements = {'files': COUNT + 1, 'full_build_seconds': round(full_seconds, 3),
                        'incremental_seconds': round(incremental_seconds, 3), 'impact_seconds': round(impact_seconds, 3),
                        'python_heap_peak_bytes': peak, 'incremental_parsed': incremental.counters['parsed'],
                        'incremental_reresolved_files': incremental.counters['resolved_files'],
                        'impact_affected_files': len(impact.affected_files)}
        target = os.environ.get('GETZILLA_GRAPH_MEASUREMENTS')
        if target:
            Path(target).write_text(json.dumps(measurements, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    unittest.main()
