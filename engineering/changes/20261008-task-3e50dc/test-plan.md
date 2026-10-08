# Test plan — Pin and checksum third-party tool downloads in the updater

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Tampered OpenGrep asset refused, previous binary kept | `tests/test_updater.py` |
| P0 | No request to releases/latest | `tests/test_updater.py` |
| P1 | Pin equals CI runner pin | `tests/test_updater.py` |
| P1 | Corrupt OSV zip refused | `tests/test_updater.py` |

## Automated checks

- Unit: `python -m unittest tests.test_updater tests.test_opengrep tests.test_install_scripts tests.test_installer`.
- Static analysis: ruff, bandit clean on changed files.
- Final: `python3 scripts/getzilla_verify.py --mode pr`.

## Manual checks

- `sha256sum` of the downloaded linux/aarch64 asset equals the pinned digest (`a730f6fd…`).
