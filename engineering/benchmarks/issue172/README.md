# GH172 research reader regression controls

This package contains three isolated regression controls and two immutable reference fixtures from the [original GH162 publication](https://github.com/Dimkox/Getzilla/tree/3247f7bc53636595a255cb7f1a787f7359e78eb6/engineering/benchmarks/issue162). The complete 108-file publication stays on `evidence/issue162-20261023` at that commit.

The controls check whole-file freshness outside a cited range, an existing readable excluded file, and a symlink in a parent directory. The reader is a fixed POSIX research fixture. These tests do not qualify an installed product read boundary.

## Exact reference identities

The files under `reference/` preserve the original bytes and Git blobs:

| Reference | Original Git blob | SHA-256 |
|---|---|---|
| [trusted_read.py](https://github.com/Dimkox/Getzilla/blob/3247f7bc53636595a255cb7f1a787f7359e78eb6/engineering/benchmarks/issue162/trusted_read.py) | `e0de5c7a3f61ea8eda3a5cc0cfc55fe016cee41d` | `ebbff17167bb6fbb42d9438483214f56d6d2cfc42fcb1c0c82596813b54b7207` |
| [test_contract.py](https://github.com/Dimkox/Getzilla/blob/3247f7bc53636595a255cb7f1a787f7359e78eb6/engineering/benchmarks/issue162/test_contract.py) | `bf1ae9358cc637e9a2cb5c26041dc25aff6c996b` | `6276fadc9510b0837c1a32569b554402428dc07d4549a1c1937b7d44db523cd6` |

Both hashes are in the original [reviewed manifest](https://github.com/Dimkox/Getzilla/blob/3247f7bc53636595a255cb7f1a787f7359e78eb6/engineering/benchmarks/issue162/reviewed-SHA256SUMS.json), whose SHA-256 is `dbc862ccb4ca67c2654272b1348a9f2a38cd28dcbb6e585f100b87112becbd57`. The [current publication manifest](https://github.com/Dimkox/Getzilla/blob/3247f7bc53636595a255cb7f1a787f7359e78eb6/engineering/benchmarks/issue162/SHA256SUMS.json) has SHA-256 `592380dcfe77a8660c015c7c696e35b2c90169454f7dc0ac349d44fe58c1c883`. Those manifests describe the original full publication; this directory contains only two of its reference files.

## Run the reader controls

Copy this directory into a new private scratch directory below the canonical repository's `.getzilla/runtime/scratch/`. Run these commands from that private copy:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 reference/test_contract.py
PYTHONDONTWRITEBYTECODE=1 TMPDIR="$PWD" python3 test_reader_regressions.py
```

The first command runs the original 12 controls. The second runs the three supplements. For guard-mutation checks, use separate private copies and keep fixture-hash verification separate from the mutated test execution so the expected assertion identifies the removed guard.

## Historical limits

The original corpus identity remains Getzilla commit `8352756ccddbb7b9f13da2da689ef633d968e30f`, with the runtime and image recorded in the original [reproduction guide](https://github.com/Dimkox/Getzilla/blob/3247f7bc53636595a255cb7f1a787f7359e78eb6/engineering/benchmarks/issue162/REPRODUCE.md) and [review status](https://github.com/Dimkox/Getzilla/blob/3247f7bc53636595a255cb7f1a787f7359e78eb6/engineering/benchmarks/issue162/review-status.md). No corpus, queries, labels, rankings, results, seal or image is copied or regenerated here. Running these reader controls on a current maintenance base is not a new retrieval benchmark or product qualification.
