# Rootless Docker image triage for #456

The official linux/amd64 manifest for Docker 29.10.1 is
`sha256:a35dc0ba082450cbb4d372f2decb416eb71676b4788fbebdb10d1cd70fb9edae`.
On 25 November 2026 Trivy 0.74.0 reported **45 occurrences, 19 CVE IDs and one Go advisory**
on both the base and the local overlay that removes the Docker CLI. Thirteen occurrences
were HIGH. The two scans used the same database updated at 13:07:24 UTC with an empty
ignore file. The overlay starts its daemon as UID 1000 and answers the Docker readiness probe.
The remaining copy of CVE-2026-85747 is in dockerd itself.

The owner reports no persistent Trust CI deployment. The hosted Trust CI acceptance
cell starts pinned Python and PostgreSQL using the runner's Docker daemon.
It does not start the Compose DinD service. The reachability assessments below apply
to the Compose deployment and to tests that explicitly start that daemon. A green
hosted acceptance cell alone cannot establish DinD runtime coverage.
[Live acceptance implementation](../../.getzilla/getzilla/live_acceptance.py)

The Compose worker starts a digest-pinned runner with network disabled and pulls disabled.
Before that, the loader contacts the daemon to pull the pinned image. The daemon runs
privileged in a rootless container on a Docker bridge, exposes port 2375 to peer services,
and has no host port mapping. Its registry access prevents using a network-isolation
assumption to dismiss daemon findings. See [Compose](../../trust-ci/compose.yaml)
and [sandbox command](../../trust-ci/src/adaptive_trust_ci/sandbox.py).

The table groups Trivy records by advisory. The version column gives affected builds
present and the first fixed module or package version advertised for that match.
Binary names refer to the image filesystem. The zlib entry covers the Alpine package.
The two x/net entries that also affect the Go standard library require the corresponding
toolchain version before transferring a conclusion across the two implementations.
The checker retains all findings. No runtime exceptions are authorized by this table.

| Advisory | Severity | Binary or package | Dependency | Installed → fixed | Reachability in Getzilla CI |
|---|---|---|---|---|---|
| [CVE-2026-10722](https://pkg.go.dev/vuln/GO-2026-6238) | LOW | containerd-shim-runc-v2, ctr, runc | github.com/cilium/ebpf | v0.17.3 → 0.22.0 | The shim and runc run for CI containers. No configured feature establishes that the affected eBPF map operation receives workload input. Reachability is unresolved. |
| [CVE-2026-128085](https://pkg.go.dev/vuln/GO-2026-6974) | MEDIUM | ctr, docker-compose | go.opentelemetry.io/otel/sdk, go.opentelemetry.io/otel/trace | v1.46.0 → 1.47.0 | The matches are in ctr and the Compose plugin. The checked CI commands do not invoke these binaries in the daemon container. Direct invocation is still possible for a trusted operator. |
| [CVE-2026-17106](https://pkg.go.dev/vuln/GO-2026-6253) | HIGH | docker-buildx | github.com/moby/go-archive | v0.2.0 → 0.3.0 | The match is in the buildx plugin. CI loads a pinned runner and executes it, with no buildx command in this daemon service. Archive handling in this plugin is outside the observed job. |
| [CVE-2026-33997](https://pkg.go.dev/vuln/GO-2026-4883) | MEDIUM | docker-buildx | github.com/docker/docker | v28.5.2+incompatible → 29.3.1 | Only the buildx plugin reports the older Moby module. The CI command set contains no plugin installation. This version match does not identify the running dockerd as version 28. |
| [CVE-2026-39821](https://pkg.go.dev/vuln/GO-2026-5026) | HIGH | runc | golang.org/x/net | v0.55.0 → 0.57.0 | The runc binary scan reports this x/net module with no matching advisory function. Its Go runtime also vendors network code. Runtime exposure through hostname handling is unproved. |
| [CVE-2026-41567](https://pkg.go.dev/vuln/GO-2026-5746) | HIGH | docker-buildx | github.com/docker/docker | v28.5.2+incompatible → no legacy fix listed, moby/moby/v2 2.0.0-beta.14 | The affected Moby module was reported in buildx. CI does pull a pinned runner, but the reported binary is a plugin that the service does not invoke. A module match does not prove daemon exposure. |
| [CVE-2026-41568](https://pkg.go.dev/vuln/GO-2026-5668) | MEDIUM | docker-buildx | github.com/docker/docker | v28.5.2+incompatible → no legacy fix listed, moby/moby/v2 2.0.0-beta.14 | The match is in buildx. CI mounts workspaces read-only and has no docker cp step into the daemon service. |
| [CVE-2026-42306](https://pkg.go.dev/vuln/GO-2026-5617) | HIGH | docker-buildx | github.com/docker/docker | v28.5.2+incompatible → no legacy fix listed, moby/moby/v2 2.0.0-beta.14 | The match is in buildx. Workspace transfer uses bind mounts. No docker cp call was identified in the checked job. |
| [CVE-2026-46600](https://pkg.go.dev/vuln/GO-2026-5942) | HIGH | runc | golang.org/x/net | v0.55.0 → 0.56.0 | The runc scan matches x/net at module level. DNS infrastructure is used for image acquisition. The affected external package and the toolchain-vendored copy require distinct version evidence. |
| [CVE-2026-4738](https://security.alpinelinux.org/vuln/CVE-2026-4738) | MEDIUM | Alpine zlib | zlib | 1.3.2-r1 → 1.4-r0 | The image contains the Alpine zlib package. The loader pulls compressed layers. A version match alone does not identify which decompressor consumes those bytes. |
| [CVE-2026-61801](https://pkg.go.dev/vuln/GO-2026-6686) | MEDIUM | runc | github.com/moby/sys/user | v0.4.0 → 0.4.1 | The runc package is present and CI starts containers with a configured user. The approved runner provides the account database. Reaching the affected operation with untrusted input is unproved. |
| [CVE-2026-78659](https://pkg.go.dev/vuln/GO-2026-6603) | MEDIUM | containerd-shim-runc-v2, ctr, runc | golang.org/x/net | v0.55.0, v0.58.0 → 0.60.0 | The shim runs in container startup. The worker uses the Docker API, but HTTP/2 server use in these particular targets is unproved. Keep the transport finding open. |
| [CVE-2026-78660](https://pkg.go.dev/vuln/GO-2026-6610) | MEDIUM | containerd-shim-runc-v2, ctr, runc | golang.org/x/net | v0.55.0, v0.58.0 → 0.60.0 | No HTTP/2 response-processing path was verified in the reported binaries during the pinned-runner test. The daemon network can reach the registry. |
| [CVE-2026-78661](https://pkg.go.dev/vuln/GO-2026-6860) | HIGH | containerd-shim-runc-v2, ctr, docker-compose, rootlesskit, runc | golang.org/x/net | v0.55.0, v0.58.0, v0.60.0 → 0.62.0 | The binaries span runtime and optional CLI plugins. No HTML document processing was identified in the job. Version-only or stripped-binary matches cannot qualify an exception. |
| [CVE-2026-78663](https://pkg.go.dev/vuln/GO-2026-6612) | MEDIUM | containerd-shim-runc-v2, ctr, runc | golang.org/x/net | v0.55.0, v0.58.0 → 0.60.0 | The bridge carries Docker API traffic. The scan does not show an HTTP/2 server in the reported targets serving that traffic. Exposure remains unresolved. |
| [CVE-2026-78669](https://pkg.go.dev/vuln/GO-2026-6611) | HIGH | containerd-shim-runc-v2, ctr, runc | golang.org/x/net | v0.55.0, v0.58.0 → 0.60.0 | The job has a reachable daemon API on its internal service network. Whether the HTTP/2 implementation in the listed binaries handles those connections is unproved. |
| [CVE-2026-85747](https://pkg.go.dev/vuln/GO-2026-6778) | MEDIUM | dockerd | github.com/docker/distribution | v2.8.3+incompatible → 2.8.4-0.20260923142519-db037680f2ac+incompatible (Go advisory) | Confirmed affected manifests.Get symbol in the unstripped dockerd binary. The runner loader requests a registry manifest. Keep blocking pending an upstream fix or exact call-path qualification. |
| [CVE-2026-97032](https://pkg.go.dev/vuln/GO-2026-6617) | MEDIUM | containerd-shim-runc-v2, ctr, runc | golang.org/x/net | v0.55.0, v0.58.0 → 0.60.0 | The reported targets include the runtime shim. No HTTP/2 HPACK use was demonstrated in the job. Static module evidence remains insufficient for an exception. |
| [CVE-2026-97045](https://pkg.go.dev/vuln/GO-2026-6866) | MEDIUM | containerd-shim-runc-v2, ctr, docker-compose, rootlesskit, runc | golang.org/x/net | v0.55.0, v0.58.0, v0.60.0 → 0.62.0 | No HTML rendering in the acceptance path was identified. Several reported binaries have incomplete symbol evidence. Runtime reachability remains unproved. |
| [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) | UNKNOWN | docker-buildx, docker-compose, dockerd, rootlesskit | golang.org/x/crypto | v0.57.0, v0.58.0 → 0.58.1-0.20261009181718-2f1f834330b2 | The reported module contains deprecated OpenPGP code. No job command requests OpenPGP processing. Upstream describes removal as the fix, requiring a compatible caller or replacement. |

## Verification and update decision

govulncheck v1.1.4 scanned the seven reported Go executables in binary mode with
the Go vulnerability database dated 24 November 2026. For stripped binaries that
version can fall back to module-level results. A function printed in fallback mode
does not prove a runtime call. The unstripped dockerd symbol table independently
contains the affected registry client function. Exact deployment reachability is
unresolved for the other runtime matches. The current repository-wide vulnerability
acceptance list cannot express an exception limited to one image digest, binary and
module version. No advisory has been added to it. [Go vulnerability tooling](https://go.dev/doc/security/vuln/)

The official catalog currently lists one numbered amd64 rootless DinD release,
29.10.1. The nightly check resolves numbered tags to linux/amd64 manifests and
flags changes, including a rebuild of the same tag. On a change, rescan the new
manifest with fresh data, check daemon readiness, and run Trust CI acceptance.
Retire the overlay after the official replacement passes. Keep the security
finding blocking until then. The December 7 review and December 8 expiry in
[#456](https://github.com/Dimkox/Getzilla/issues/456) remain in force.
[Official Docker image catalog](https://github.com/docker-library/official-images/blob/master/library/docker)

| Evidence | SHA-256 |
|---|---|
| Original Trivy JSON | `ba011f0701673d1d15e469b8edc2c27e53ed029bbce0455648ef243a1b242c0b` |
| Overlay Trivy JSON | `95150c5ce1b192887182e97275cecf9d5f1b8412de96064d67805cae812b1e51` |
| containerd-shim-runc-v2 | `4e737e85858957940d3f2099234d86883b68be6f800c7d5864d3b328d1c90ab7` |
| ctr | `67188d2a113a8d4ef41645787e60cc65e9eafc99e746b0cde334f92465be154b` |
| docker-buildx | `903090816da68f8bc1a2ff5346dd163a5adacfce4548d003c75df42cd47a9bf4` |
| docker-compose | `b8840f5008c447f41fce0a57ae3adeab42c89b1eb6e6012524bcabbfb4ffbaf6` |
| dockerd | `5d758c2b8fbe38313f9c15bb124cc1101719dc7521771e9e3745846e18a0c126` |
| rootlesskit | `9a7693963bf3f3e8b77a6077ede843f7b6d77a5cad2d6cf35da116731d440aeb` |
| runc | `dbe0864ec684fed2aa408de200f76db14266dc4ce7b55accb7367da539c8c895` |

## Archive import and registry manifest verification

The linux/amd64 dockerd executable reports Moby revision
`54cd494d0b39abfc7a958fcc876f706271f8b909`. GO-2026-6778 identifies
`(*manifests).Get` in three package paths. This binary contains
`github.com/docker/distribution/registry/client.(*manifests).Get`.
The other advisory paths are `github.com/distribution/distribution/registry/client`
and `github.com/distribution/distribution/v3/internal/client`.
[Go advisory](https://pkg.go.dev/vuln/GO-2026-6778)

**(a) Archive load.** For a self-contained local archive, the API handler
`imageRouter.postImagesLoad` calls the image service's `LoadImage`. On the classic
overlay2 backend, `daemon/images.ImageService.LoadImage` delegates to
`tarexport.(*tarexporter).Load` and `loadLayer`. These read the archive's manifest,
config and layers, compare the registered diff IDs, and create a local config ID.
On the containerd backend, `ImageService.LoadImage` calls `importImages`,
`Client.Import` and `archive.ImportIndex` on the local stream and content store.
Neither archive path invokes the advisory's registry client function.
The classic registry pull path can call it through `puller.pullTag` and
`manifestStore.Get`. The answer concerns the supplied archive and exact backends.
[Classic load](https://github.com/moby/moby/blob/54cd494d0b39abfc7a958fcc876f706271f8b909/daemon/internal/image/tarexport/load.go)
[Containerd load](https://github.com/moby/moby/blob/54cd494d0b39abfc7a958fcc876f706271f8b909/daemon/containerd/image_exporter.go)
[Registry manifest store](https://github.com/moby/moby/blob/54cd494d0b39abfc7a958fcc876f706271f8b909/daemon/internal/distribution/manifest.go)

**(b) Verification order.** In the affected function the request uses the supplied
digest, but the response body is unmarshalled and returned without comparing its hash
with that digest. An optional response header is a registry assertion. The caller
can subsequently commit content using the expected digest; failure to persist the
manifest is logged and the caller can still return it. The missing binding is at
the registry response boundary, before any independent caller-side verification.
A local importer must establish the pinned manifest, config and layer hashes before
passing bytes to Docker. On classic overlay2 it must also account for the distinction
between a repository digest and the image's config ID after load.
[Vendored client](https://github.com/moby/moby/blob/54cd494d0b39abfc7a958fcc876f706271f8b909/vendor/github.com/docker/distribution/registry/client/repository.go)

### Worker integration stop on classic overlay2

In a local diagnostic using rootless Docker 29.10.1, the project worker connected
through the shared Unix socket. The daemon had no TCP listener on 2375 or 2376.
The fixture used the retained runner image pinned at
`getzilla-trust-ci-runner@sha256:e0ed5e4328eb71ccf2a2708f73470fa505e0f9cf5ddab32ec07e628258d69634`.
The archive's index, amd64 manifest, config and nine layers verified before load.
After load the returned config ID matched
`sha256:e4687544676c951ef751844f342657b5c4d485a4b9022bf22fb5c5b38928fb3b`.
The daemon reported `RepoDigests=[]`. Launching the job with the project's
`ContainerExecutor`, the named digest, `--pull never` and `--network none`
returned exit 125 (No such image). The job did not start, so isolation from
inside a running job remains unverified. This local diagnostic does not establish
eligibility for a CVE exception.

### Offline worker verification on 25 November

The signed-policy format now carries the registry manifest and amd64 config digest.
A local run used the retained runner above, a temporary HTTPS registry and disposable keys.
The fetch container had no daemon socket. The offline loader verified all nine layers
and the config, imported the reconstructed archive and inspected the exact local ID.
The worker launched the job using the config ID. Inside that job, loopback refused
connections to ports 2375 and 2376, the DinD bridge gateway was unreachable and
none of the three Docker socket paths existed. The engine's only network was an
internal isolated bridge. Its namespace had no IPv4 default route and could not
reach the registry used by the fetch container. The probe and its invocation are
in [the integration test](../../trust-ci/tests/run_offline_runner.sh).

The diagnostic exception covers the single linux/amd64 base manifest listed above,
the binary `usr/local/bin/dockerd`, the affected module version and CVE-2026-85747.
The checker verifies the tested deployment controls, the sole use of that upstream
manifest as the base of the Trust CI daemon, and the official catalog and current
amd64 digest during acquisition. A catalog change, a new digest, an unavailable
upstream check or expiry at 00:00 UTC on 25 December ends eligibility. A change
to the catalog can therefore end eligibility before a fix is confirmed. KEV and EPSS evaluations receive the original vulnerability evidence.

The owner separately approved the Docker CLI finding in that same build input,
subject to independent review and the same expiry and upstream checks. The checker
compares its executable hash, layer, path and config with the recorded finding.
It examines every other imported image in the complete inventory. For images
whose layers contained that executable, it checks all final file hashes after
whiteouts and hardlink resolution. For the built daemon it also verifies removal
of the original path. Missing evidence or a surviving copy blocks admission.
The diagnostic artifact `security-dind-cli.json` records each image identity and
the evidence used for removal. All other vulnerability findings retain their
ordinary disposition.

The released amd64 client has SHA-256
`f71558dcbb6c2e028fc5c7cf67270ef6fafd9cc865570b73700d405b2c2ebc02`.
Its Go build information identifies Go 1.27.4 and CLI commit `c48360f`.
The annotated v29.10.1 tag resolves to `c48360f51c53d2029ab6721ad4d012f9e14df846`.
The checker scans all 94 upstream vendored module versions, the CLI root module
and the standard library against the same fresh Trivy database used for images.
The component list includes dependencies for all platforms. Missing packages,
an unavailable scan or additional findings block the result. Only the exact
distribution module finding can proceed to the independent removal check.
[Upstream vendor manifest](https://github.com/docker/cli/blob/c48360f51c53d2029ab6721ad4d012f9e14df846/vendor/modules.txt)

### Seven HIGH findings after isolating the daemon

The offline loader and Unix socket supersede the pull and TCP configuration described in the original scan above. The following dispositions use the pinned amd64 binaries. They create no additional scanner exceptions.

| CVE | Evidence in the selected binaries | Fix and disposition |
|---|---|---|
| CVE-2026-17106 | Module match in the buildx plugin. The loader and worker never invoke buildx. | Update go-archive to v0.3.0 or remove the unused plugin and rescan the resulting filesystem. |
| CVE-2026-41567 | Affected Moby symbols in buildx. No CI step invokes this plugin. | Upstream lists moby/v2 v2.0.0-beta.14. Retire the unused plugin or use a fixed upstream build. |
| CVE-2026-42306 | Affected Moby symbols in buildx. The job does not invoke the plugin. | Same upstream module migration. Verify plugin removal against the final filesystem. |
| CVE-2026-39821 | Module-level x/net match in runc, which starts jobs. Runtime reachability remains unresolved. | Require a fixed runtime built with x/net v0.57.0 or later. |
| CVE-2026-46600 | Module-level x/net match in runc. Isolation alone cannot establish that local resolver handling is unreachable. | Require x/net v0.56.0 or later. |
| CVE-2026-78661 | Affected HTML parser symbols in the runtime shim and ctr. Module-level matches also occur in runc, rootlesskit and Compose. | Require x/net v0.62.0 or later. The current job has no demonstrated HTML path, but the active shim prevents a binary-wide exemption. |
| CVE-2026-78669 | Affected HTTP/2 symbols in the runtime shim and ctr, plus a module match in runc. The shim participates in job startup. | Require x/net v0.60.0 or later. Keep blocking until the runtime is fixed or its inputs establish non-reachability. |
