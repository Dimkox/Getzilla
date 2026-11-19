# Reproduce the fixed experiment

Use an owned directory below the canonical repository `.getzilla/runtime/scratch/`. Keep Getzilla commit `8352756ccddbb7b9f13da2da689ef633d968e30f` available as a Git object. Scripts use `/home/pall/projects/getzilla` as that canonical source root. They never read a live working-tree source file for corpus materialization.

Run these commands in dependency order. Save each output and exit. Keep the current sealed `data/` files. Do not regenerate qrels after seeing results. A fresh experimental query set needs a new independent review.

```bash
python3 prepare.py
python3 prepare_model.py
docker build --cpu-quota 200000 --cpu-period 100000 -t getzilla-issue162-tools:local .
python3 launch.py prepare
python3 launch.py run
python3 git_parity.py
python3 check_artifacts.py
python3 finalize.py
```

`launch.py run` checks the independent-review seal before indexing. It runs the two corpora in parallel with one CPU each. It then runs three fresh-process model loads with at most two processes. All inference has network disabled. Network preparation downloads immutable raw source files, pinned model files and public tool packages. It does not upload source. `git_parity.py` fetches the exact small upstream commit into an owned bare repository and compares direct Git blobs with raw and Gitless copies.

The four direct Python tool versions are pinned in the Dockerfile. `execution/packages.stdout` records the actual transitive environment. The original image identity is in `execution/image.stdout`. Rebuilding from the Dockerfile can resolve newer transitive versions. Use the recorded image digest or recreate the captured versions for exact tool parity. Model and context-tokenizer asset hashes are in `data/`. Inference needs the prepared codec cache because its network is disabled.

Use `docker build -f Dockerfile.replay -t getzilla-issue162-tools:local .` to install the captured package versions for a replay. This replay Dockerfile was not the image build used for the recorded measurements. Package file hashes are not wheel-level lock hashes.

The bundle excludes model binaries, Python tool caches, duplicate corpus trees and vector arrays. `prepare.py` restores the sources from exact raw URLs and Git blobs. `prepare_model.py` restores and verifies the model. Full rankings, manifests, labels, settings, metrics, supporting tests and qrel snippets remain in the bundle. The report states which metrics are bounded proxies.

Do not run the product PR verifier for this source-tree no-op research contour. Run the experiment's controls and independent evidence review. Product integration requires a separate isolated branch and its normal route gates.
