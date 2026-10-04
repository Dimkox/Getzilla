# Getzilla Trust CI onboarding

## Objective

Make the existing self-hosted Trust CI service verify `Dimkox/Getzilla` pull requests exactly as it verifies the predecessor repository, without renaming or redeploying the service. Getzilla reuses the deployed identity on purpose: the GitHub App `adaptive-trust-ci` (App ID `4694114`), the Check Run context `adaptive-trust-ci/verified@<policy-sha12>`, the `adaptive_trust_ci` package and the server paths under `/etc/adaptive-trust-ci`, `/srv/adaptive-trust-ci` and `/opt/adaptive-grok-build-pro/trust-ci`.

Nothing in this repository changes the deployed service. Every step below is an operator action on the CI host or on GitHub, reviewed like any other change to merge authority.

## What is already true

- The GitHub App `adaptive-trust-ci` is installed with **All repositories**, so `Dimkox/Getzilla` already sends pull-request webhooks to the service.
- The service rejects unknown repositories before enqueue. Until the deployed policy names `Dimkox/Getzilla`, Getzilla pull requests get no Check Run.

## 1. Bring the deployed policy to catalog mode

Repository-scoped profiles exist only in catalog mode (`repository_profiles`). Legacy mode (`allowed_repositories` plus root `commands` and `holdout`) runs one command set for every repository, and those commands name predecessor paths such as `scripts/grok_verify.py`, which do not exist in Getzilla.

Check which shape is deployed:

```bash
sudo python3 -c "import json; p=json.load(open('/opt/adaptive-grok-build-pro/trust-ci/runtime/policy.json')); print('catalog' if 'repository_profiles' in p else 'legacy')"
```

If it prints `legacy`, convert it following [Profile rollout and rollback](../../trust-ci/README.md#profile-rollout-and-rollback): move the existing root `commands` and `holdout` into a `Dimkox/adaptive-grok-build-pro` profile unchanged, add the paired `holdout.host_path`, and remove `allowed_repositories`.

## 2. Add the Getzilla profile

Add this profile next to the predecessor's. It is the `Dimkox/Getzilla` entry of [`trust-ci/config/policy.example.json`](../../trust-ci/config/policy.example.json); only the holdout digest changes to the digest of the holdout you install in step 3.

```json
{
  "repository": "Dimkox/Getzilla",
  "commands": [
    {"name": "root-unittest", "argv": ["python3", "-m", "unittest", "discover", "-s", "tests"], "timeout_seconds": 900, "required": true},
    {"name": "trust-ci-unittest", "argv": ["python3", "-m", "unittest", "discover", "-s", "trust-ci/tests"], "timeout_seconds": 900, "required": true},
    {"name": "compileall", "argv": ["python3", "-m", "compileall", "-q", ".getzilla/getzilla", "scripts", "trust-ci/src"], "timeout_seconds": 300, "required": true},
    {"name": "repository-verification", "argv": ["python3", "scripts/getzilla_verify.py", "--mode", "pr", "--no-record", "--json"], "timeout_seconds": 1200, "required": true}
  ],
  "holdout": {
    "path": "/etc/adaptive-trust-ci/holdout/getzilla",
    "host_path": "/etc/adaptive-trust-ci/holdout/getzilla",
    "digest": "<output of holdout-digest from step 3>",
    "commands": [
      {"name": "adaptive-holdout", "argv": ["python3", "/holdout/validate.py", "/workspace"], "timeout_seconds": 300, "required": true}
    ]
  }
}
```

The runner image does not change: Getzilla needs the same Python toolchain as the predecessor.

## 3. Install a Getzilla holdout bundle

The deployed holdout checks named source files, so the predecessor's bundle fails on Getzilla. Copy it and apply the same path mapping as the rename, then pin its digest:

```bash
sudo cp -a /etc/adaptive-trust-ci/holdout/adaptive-grok-build-pro /etc/adaptive-trust-ci/holdout/getzilla
sudo find /etc/adaptive-trust-ci/holdout/getzilla -type f -name '*.py' -exec sed -i \
  -e 's#\.grok-stack/adaptive_grok#.getzilla/getzilla#g' \
  -e 's#\.grok-stack#.getzilla#g' \
  -e 's#scripts/grok_\([a-z_]*\)\.py#scripts/getzilla_\1.py#g' \
  -e 's#adaptive_factory#getzilla_factory#g' \
  -e 's#adaptive_delivery#getzilla_delivery#g' {} +
adaptive-trust-ci holdout-digest --path /etc/adaptive-trust-ci/holdout/getzilla
```

Use the source directory your deployment actually mounts if it differs. Review the diff of the copied bundle before trusting it; the example bundle in [`trust-ci/holdout.example`](../../trust-ci/holdout.example/) shows the expected result.

## 4. Mind the policy epochs

- Converting legacy to catalog changes the predecessor's policy digest, so its Check Run name changes. Re-run `branch-protect` for `Dimkox/adaptive-grok-build-pro` with the new name after you observe a green App-owned check under it, exactly as in [Trust CI rollout](trust-ci-rollout.md).
- Once the deployed policy is already in catalog mode, adding the Getzilla profile rotates only Getzilla's epoch.

## 5. Prove, then protect Getzilla

Follow [Prove the App-owned policy epoch before protection](trust-ci-rollout.md#prove-the-app-owned-policy-epoch-before-protection) on a small Getzilla pull request, then bind `main`:

```bash
TRUST_CI_GITHUB_ADMIN_TOKEN=<temporary-admin-token> \
TRUST_CI_GITHUB_APP_ID='4694114' \
adaptive-trust-ci branch-protect \
  --policy /opt/adaptive-grok-build-pro/trust-ci/runtime/policy.json \
  --repository Dimkox/Getzilla \
  --branch main \
  --required-reviews 0
```

Applying protection before a green App-owned check exists can lock the repository.

## Why Getzilla started from a direct import

The external holdout refuses a pull request that changes more than 100 change-spec files, and pull-request verification compares the head against its base. A single pull request that imports the whole predecessor tree cannot pass either check, so the verbatim import is the base commit of `main` and later work arrives in ordinary, verifiable pull requests.

## Later: renaming the service itself

Renaming the App, the Check Run context, the `adaptive_trust_ci` package, the server paths and the L5 runtime (`/opt/adaptive-l5`, `/etc/adaptive-l5`, `/var/lib/adaptive-l5`) is a separate, planned cutover with a migration and downtime window. It is intentionally not part of the Getzilla rename.
