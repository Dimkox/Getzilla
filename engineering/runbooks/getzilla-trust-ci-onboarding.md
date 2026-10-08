# Getzilla Trust CI onboarding

## Objective

Make the existing self-hosted Trust CI service verify `Dimkox/Getzilla` and **every other `Dimkox` repository with Getzilla installed**, without renaming the service. Getzilla reuses the deployed identity on purpose: the GitHub App `adaptive-trust-ci` (App ID `4694114`), the Check Run context `adaptive-trust-ci/verified@<policy-sha12>`, the `adaptive_trust_ci` package and the server paths under `/etc/adaptive-trust-ci` and `/opt/adaptive-grok-build-pro/trust-ci`.

Nothing in this repository changes the deployed service. Every step below is an operator action on the CI host or in GitHub settings.

## How "any repository" works

The policy catalog has two kinds of profiles:

- **exact profiles** (`repository_profiles`) for repositories with their own commands and holdout: `Dimkox/adaptive-grok-build-pro` (predecessor) and `Dimkox/Getzilla`;
- an **owner profile** (`owner_profiles`) for every other `Dimkox/*` repository. It runs `python3 scripts/getzilla_verify.py --mode pr --no-record --json` and the generic [consumer holdout](../../trust-ci/holdout.consumer.example/validate.py), which refuses repositories without Getzilla installed.

Repositories of any other owner are still rejected before enqueue, even if they install the App. That is what makes it safe to make the App public.

Owner profiles need the Trust CI code from this repository. The currently deployed code understands exact profiles only and silently ignores `owner_profiles`.

## 0. Variables on the CI host

```bash
CHECKOUT=/opt/adaptive-grok-build-pro          # deployed Trust CI checkout
POLICY=$CHECKOUT/trust-ci/runtime/policy.json   # deployed policy
ROOT=/etc/adaptive-trust-ci/holdout            # TRUST_CI_HOLDOUT_PATH and TRUST_CI_HOLDOUT_HOST_PATH
SRC=/opt/getzilla-src                          # reviewed Getzilla source
REF=<reviewed Getzilla commit on main>
tci() { sudo -E PYTHONPATH="$SRC/trust-ci/src" PYTHONDONTWRITEBYTECODE=1 python3 -m adaptive_trust_ci.cli "$@"; }
```

If `TRUST_CI_HOLDOUT_PATH` and `TRUST_CI_HOLDOUT_HOST_PATH` differ in your env files, stage the bundles under both and pass both roots to the planner.

## 1. Fetch the reviewed Getzilla source

```bash
sudo git clone https://github.com/Dimkox/Getzilla.git "$SRC"
sudo git -C "$SRC" checkout --detach "$REF"
```

## 2. Stage the holdout bundles (drain workers first)

Catalog holdouts must be strict subdirectories of the trusted root, so the current bundle is copied unchanged into a per-repository directory.

```bash
LEGACY=$(sudo python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['holdout']['path'])" "$POLICY")
LEGACY_DIGEST=$(sudo python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['holdout']['digest'])" "$POLICY")
sudo install -d "$ROOT/adaptive-grok-build-pro" "$ROOT/getzilla" "$ROOT/owner-dimkox"
sudo find "$LEGACY" -mindepth 1 -maxdepth 1 \
  ! -name adaptive-grok-build-pro ! -name getzilla ! -name owner-dimkox \
  -exec cp -a {} "$ROOT/adaptive-grok-build-pro/" \;
test "$(tci holdout-digest --path "$ROOT/adaptive-grok-build-pro")" = "$LEGACY_DIGEST" && echo predecessor bundle OK

# Getzilla: same bundle, renamed paths
sudo cp -a "$ROOT/adaptive-grok-build-pro/." "$ROOT/getzilla/"
sudo find "$ROOT/getzilla" -type f -name '*.py' -exec sed -i \
  -e 's#\.grok-stack/adaptive_grok#.getzilla/getzilla#g' \
  -e 's#\.grok-stack#.getzilla#g' \
  -e 's#scripts/grok_\([a-z_]*\)\.py#scripts/getzilla_\1.py#g' \
  -e 's#adaptive_factory#getzilla_factory#g' \
  -e 's#adaptive_delivery#getzilla_delivery#g' {} +

# every other Dimkox repository with Getzilla installed
sudo cp -a "$SRC/trust-ci/holdout.consumer.example/." "$ROOT/owner-dimkox/"
sudo find "$ROOT" -name __pycache__ -prune -exec rm -rf {} +
```

If the deployed policy is already a catalog, skip the `LEGACY` lines: copy the predecessor's existing profile directory instead.

## 3. Plan the new policy

```bash
sudo PYTHONPATH="$SRC/trust-ci/src" PYTHONDONTWRITEBYTECODE=1 python3 -m adaptive_trust_ci.onboarding \
  --policy "$POLICY" \
  --out "$CHECKOUT/trust-ci/runtime/policy.catalog.json" \
  --owner Dimkox \
  --holdout-root "$ROOT" --holdout-host-root "$ROOT" \
  --getzilla-bundle "$ROOT/getzilla" \
  --owner-bundle "$ROOT/owner-dimkox"
```

The planner never touches the deployed policy. It prints, per repository, the check name before and after (`rerun_branch_protect: true` means branch protection must be rebound) and the holdout bundles with their digests. Review the diff between `policy.json` and `policy.catalog.json` before installing it.

## 4. Deploy the Trust CI code that understands owner profiles

Point the deployed checkout at Getzilla and roll out API and worker exactly as in [Trust CI rollout](trust-ci-rollout.md) (build, pin image digests, verify the supply chain). The runner image does not change.

```bash
sudo git -C "$CHECKOUT" remote set-url origin https://github.com/Dimkox/Getzilla.git
sudo git -C "$CHECKOUT" fetch origin
sudo git -C "$CHECKOUT" checkout --detach "$REF"
sudo cp "$CHECKOUT/trust-ci/runtime/policy.catalog.json" "$POLICY"
# then: build/pin api and worker, docker compose up -d api worker, per trust-ci-rollout.md
```

`runtime/` is untracked, so the checkout switch keeps the deployed policy, keys and env files.

## 5. Prove, then protect each repository

For Getzilla, the predecessor and each `Dimkox` repository you want gated: open a small pull request, confirm the App-owned `adaptive-trust-ci/verified@<epoch>` Check Run on its exact head (see [Prove the App-owned policy epoch](trust-ci-rollout.md#prove-the-app-owned-policy-epoch-before-protection)), then bind its `main`. `branch-protect` now resolves the repository's own profile, so the check name comes from the policy:

```bash
export TRUST_CI_GITHUB_ADMIN_TOKEN=<temporary-admin-token> TRUST_CI_GITHUB_APP_ID=4694114
for repo in Dimkox/Getzilla Dimkox/adaptive-grok-build-pro; do   # add more Dimkox repos here
  tci branch-protect --policy "$POLICY" --repository "$repo" --branch main --required-reviews 0
done
unset TRUST_CI_GITHUB_ADMIN_TOKEN
```

Protecting a repository before a green App-owned check exists for its current epoch locks it. The predecessor's epoch changes when a legacy policy becomes a catalog; rebind it after its first green check under the new name.

## 6. Make the GitHub App public

1. Deploy the worker from this repository (step 4) and set `TRUST_CI_GITHUB_INSTALLATION_ID=auto` in `env/worker.env`, then restart the worker. A numeric ID would keep the worker publishing only to your own account's installation.
2. GitHub → **Settings → Developer settings → GitHub Apps → adaptive-trust-ci → Advanced → Danger zone → Make public**.
3. Optional: fill in the App's description and homepage (`https://github.com/Dimkox/Getzilla`) so its public install page explains what it does.

Making it public is effectively one-way: GitHub does not let a public App become private again while it is installed on other accounts.

Strangers can install it, but the service only enqueues repositories covered by an exact or owner profile; everything else is rejected before any code runs on the CI host.

## 7. Paid access for other accounts

Trust CI runs on owned hardware, so it is a paid service for **private** repositories; public repositories are gated by GitHub Actions for free (`scripts/getzilla_ci.py --write`). An account asks for access with the [Trust CI access issue form](https://github.com/Dimkox/Getzilla/issues/new?template=trust-ci-access.yml), is invoiced by hand, and gets access once it has paid:

```bash
cd "$DEPLOY"
PYTHONPATH="$SRC/trust-ci/src" python3 -m adaptive_trust_ci.customers add \
  --policy runtime/policy.json --out runtime/policy.next.json --owner <login> \
  --holdout-root "$TRUST_CI_HOLDOUT_PATH" --holdout-host-root "$TRUST_CI_HOLDOUT_HOST_PATH" \
  --bundle "$SRC/trust-ci/holdout.consumer.example"
```

The report names the bundle to copy (`install_bundle.to`) and the one new check name; no other profile's check changes. Copy the bundle, review the planned file, swap it in for `runtime/policy.json`, and restart the API and workers. The account then installs the App on its private repositories and binds branch protection after the first green check. When access lapses, `customers remove --owner <login>` plans the reverse change; `customers list --policy runtime/policy.json` shows who has access.

## Why Getzilla started from a direct import

The external holdout refuses a pull request that changes more than 100 change-spec files, and pull-request verification compares the head against its base. A single pull request that imports the whole predecessor tree cannot pass either check, so the verbatim import is the base commit of `main` and later work arrives in ordinary, verifiable pull requests.

## Later: renaming the service itself

Renaming the App, the Check Run context, the `adaptive_trust_ci` package, the server paths and the L5 runtime (`/opt/adaptive-l5`, `/etc/adaptive-l5`, `/var/lib/adaptive-l5`) is a separate, planned cutover with a migration and downtime window. It is intentionally not part of the Getzilla rename.
