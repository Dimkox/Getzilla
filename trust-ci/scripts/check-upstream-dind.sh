#!/usr/bin/env bash
# Compare every numbered official rootless DinD build for amd64 with the triage baseline.
set -euo pipefail
baseline='sha256:a35dc0ba082450cbb4d372f2decb416eb71676b4788fbebdb10d1cd70fb9edae'
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export DOCKER_CONFIG="$work/docker"
mkdir -m 700 "$DOCKER_CONFIG"
curl --fail --silent --show-error --proto '=https' --max-time 30 --max-filesize 131072 \
  https://raw.githubusercontent.com/docker-library/official-images/master/library/docker > "$work/library"
awk '/^Tags: / {sub(/^Tags: /,""); gsub(/, /,"\n"); print}' "$work/library" |
  awk '/^[0-9]+\.[0-9]+\.[0-9]+-dind-rootless$/' | sort -Vu > "$work/tags"
count=$(wc -l < "$work/tags")
if (( count == 0 || count > 32 )); then
  echo 'Official rootless tag inventory missing or outside the supported bound' >&2
  exit 1
fi
changed=0
while IFS= read -r tag; do
  timeout 45 docker buildx imagetools inspect --raw "docker.io/library/docker:$tag" > "$work/index"
  digest=$(jq -er '[.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64")
    | .digest] | if length == 1 then .[0] else error("ambiguous platform") end
    | select(test("^sha256:[a-f0-9]{64}$"))' "$work/index")
  echo "$tag $digest"
  if [[ "$digest" != "$baseline" ]]; then
    changed=1
  fi
done < "$work/tags"
if (( changed )); then
  echo 'Review the changed official digest against issue #456, rescan it and run Trust CI acceptance.' >&2
  exit 1
fi
