#!/usr/bin/env bash
# Three local image inputs: retained runner name@digest, built worker, built DinD.
set -euo pipefail
runner=${1:?local runner name@digest}
worker=${2:?built worker image}
engine=${3:?built dind image}
root=$(cd "$(dirname "$0")/.." && pwd)
project=$(mktemp -d)
name="offline-456-$$"
compose=(docker compose -p "$name" --project-directory "$project" -f "$project/compose.yaml" -f "$project/fixture.yaml")
cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$project"
}
trap cleanup EXIT
mkdir -p "$project"/{env,runtime,holdout,fixture}
for env in postgres common migration api worker; do touch "$project/env/$env.env"; done
cp "$root/env/common.env.example" "$project/env/common.env"
sed -e 's/REPLACE_WITH_APP_ID/1/' -e 's/REPLACE_WITH_INSTALLATION_ID_OR_auto/1/' "$root/env/worker.env.example" > "$project/env/worker.env"
cp "$root/compose.yaml" "$project/compose.yaml"
export TRUST_CI_WORKER_IMAGE="$worker" TRUST_CI_DIND_IMAGE="$engine" TRUST_CI_POSTGRES_IMAGE="$worker" TRUST_CI_API_IMAGE="$worker"
export TRUST_CI_HOLDOUT_SOURCE_PATH="$project/holdout"
export TRUST_CI_RUNNER_IMAGE="registry.test:4443/suite/runner@${runner##*@}"
docker save -o "$project/fixture/source.tar" "$runner"
python3 - "$project" "$root" <<'PY'
import hashlib, json, os, pathlib, re, shutil, sys, tarfile
p = pathlib.Path(sys.argv[1])
src = p/'fixture'
policy = json.loads((pathlib.Path(sys.argv[2])/'config/policy.example.json').read_bytes())
image = os.environ['TRUST_CI_RUNNER_IMAGE']
with tarfile.open(src/'source.tar', 'r:') as arc:
    for item in arc:
        if item.isfile() and re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', item.name):
            with (src/item.name.rsplit('/', 1)[1]).open('xb') as out:
                shutil.copyfileobj(arc.extractfile(item), out)
def document(key):
    raw = (src/key.removeprefix('sha256:')).read_bytes()
    assert 'sha256:' + hashlib.sha256(raw).hexdigest() == key
    return json.loads(raw)
pin = image.split('@')[1]
manifest = document(pin)
if 'manifests' in manifest:
    selected, = [d for d in manifest['manifests'] if d.get('platform') == {'os': 'linux', 'architecture': 'amd64'}]
    manifest = document(selected['digest'])
config = manifest['config']['digest']
document(config)
policy['sandbox'].update(image=image, runner_manifest_digest=pin, runner_config_digest=config)
(p/'runtime/policy.json').write_text(json.dumps(policy))
(src/'source.tar').unlink()
PY
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=registry.test -addext subjectAltName=DNS:registry.test -keyout "$project/fixture/key" -out "$project/fixture/cert" >/dev/null 2>&1
cat > "$project/fixture/serve.py" <<'PY'
import http.server, re, ssl
class Handler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        match = re.fullmatch(r'/v2/suite/runner/(manifests|blobs)/sha256:([0-9a-f]{64})', path)
        return '/fixture/' + match[2] if match else '/fixture/absent'
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/fixture/cert', '/fixture/key')
server = http.server.ThreadingHTTPServer(('0.0.0.0', 4443), Handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
cat > "$project/fixture.yaml" <<'YAML'
services:
  fixture:
    image: ${TRUST_CI_WORKER_IMAGE}
    user: "0:0"
    volumes: ["./fixture:/fixture:ro"]
    entrypoint: ["python", "/fixture/serve.py"]
    networks:
      registry:
        aliases: [registry.test]
    healthcheck:
      test: ["CMD","python","-c","import socket; socket.create_connection(('127.0.0.1',4443),1).close()"]
      interval: 1s
      timeout: 2s
      retries: 10
  runner-fetch:
    environment:
      SSL_CERT_FILE: /test-ca
    volumes: ["./fixture/cert:/test-ca:ro"]
    depends_on:
      fixture:
        condition: service_healthy
YAML
"${compose[@]}" up -d runner-loader || { "${compose[@]}" logs --no-color runner-fetch docker-engine fixture; exit 1; }
loader=$("${compose[@]}" ps -aq runner-loader)
test "$(docker wait "$loader")" = 0 || { "${compose[@]}" logs runner-loader runner-fetch; exit 1; }
daemon=$("${compose[@]}" ps -q docker-engine)
fixture=$("${compose[@]}" ps -q fixture)
registry_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$fixture")
test "$(docker network inspect -f '{{.Internal}}' "${name}_executor")" = true
test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$daemon")" = 1
docker exec "$daemon" sh -ec 'if grep -Eq "^[^[:space:]]+[[:space:]]+00000000[[:space:]]" /proc/net/route || nc -zn -w2 "$1" 4443; then exit 1; fi; echo "Engine has no default IPv4 route and cannot connect to registry $1"' sh "$registry_ip"
# The diagnostic worker uses the same socket, policy, groups and workspace as deployment.
"${compose[@]}" run --rm --no-deps -v "$root/tests/runner_network_probe.py:/probe.py:ro" -v "$root/tests/job_daemon_isolation.py:/job-probe.py:ro" --entrypoint python worker /probe.py
echo 'Offline runner integration passed'
