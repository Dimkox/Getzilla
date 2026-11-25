"""Bound software ownership for the source copies and pinned runner downloads."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .security_artifacts import read_file

# These inventories were independently matched path-by-path against the pinned
# Node TAR and the CRC-validated Nuitka member table of the pinned OpenGrep ELF.
# An extra or changed installed file rejects the entire corresponding match.
_NODE = ("node-v24.22.0-linux-x64.tar.xz", "cc2f601cee82d9a5a233302fe307abc600727035fd7d2c3a3571755989e95008",
         "opt/node/", 1228, "99ef7081113b37fc7e9ff5fcb0b7ce5f26d0b9a9cd13c7c88e32bd632799f59d")
_OPENGREP = ("opengrep_manylinux_x86", "d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4",
             "home/ci/.cache/opengrep/v1.30.1/", 78, "88d40120bdb0bc3a87b91bc8b9ce55427bd082af2b46f6f4ee56a75a7f4c158e")


def archive_origins(software):
    result = []
    for name, source_hash, prefix, count, expected in (_NODE, _OPENGREP):
        rows = sorted((r["path"], r["bytes"], r["sha256"]) for r in software if r["path"].startswith(prefix))
        if len(rows) != count:
            continue
        encoded = json.dumps(rows, separators=(",", ":")).encode()
        if hashlib.sha256(encoded).hexdigest() == expected:
            result.append((name, {"source_archive_sha256": source_hash, "installed_members_sha256": expected},
                           [r[0] for r in rows]))
    if any(r["path"] == "usr/local/bin/opengrep" and r["sha256"] == _OPENGREP[1] for r in software):
        result.append(("opengrep-executable", {"source_archive_sha256": _OPENGREP[1]}, ["usr/local/bin/opengrep"]))
    return result


def project_origins(software, root):
    result = []
    for row in software:
        path = row["path"]
        if path == "usr/local/lib/install_public_checker.py":
            source = "trust-ci/scripts/install_public_checker.py"
        elif path.startswith("opt/adaptive-trust-ci/build/lib/"):
            source = "trust-ci/src/" + path.removeprefix("opt/adaptive-trust-ci/build/lib/")
        elif path.startswith("opt/adaptive-trust-ci/"):
            source = "trust-ci/" + path.removeprefix("opt/adaptive-trust-ci/")
        else:
            continue
        try:
            data = read_file(Path(root), source, 2 * 1024 * 1024)
        except (OSError, ValueError):
            continue
        if len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"]:
            result.append({"source": source, "path": path, "sha256": row["sha256"]})
    return result


# Verified against upstream source files, archive members or the pinned CPython build.
_UPSTREAM_FILES = {
    (
        "usr/local/bin/containerd-shim-runc-v2",
        "4e737e85858957940d3f2099234d86883b68be6f800c7d5864d3b328d1c90ab7",
        "sha256:fdf62cd757ced966ec0323b1833d18f93a1e6617705d825d43af900dfd662910",
    ): "https://download.docker.com/linux/static/stable/x86_64/docker-29.10.1.tgz#061642059fa7f2ed9b2f04a327a951cff4249585cf04b2661c2a6539197c9962/docker/containerd-shim-runc-v2",
    (
        "usr/local/bin/ctr",
        "67188d2a113a8d4ef41645787e60cc65e9eafc99e746b0cde334f92465be154b",
        "sha256:fdf62cd757ced966ec0323b1833d18f93a1e6617705d825d43af900dfd662910",
    ): "https://download.docker.com/linux/static/stable/x86_64/docker-29.10.1.tgz#061642059fa7f2ed9b2f04a327a951cff4249585cf04b2661c2a6539197c9962/docker/ctr",
    (
        "usr/local/bin/dind",
        "673bb7adc8b463b56e9e929672ea74b40951f655a023d0b9801f46c9da4bc509",
        "sha256:21f6d15792afa1fa17a8ae24fea133929514be58ade0f07e0589d55c54a97f33",
    ): "https://github.com/moby/moby/blob/8d9e3502aba39127e4d12196dae16d306f76993d/hack/dind",
    (
        "usr/local/bin/docker",
        "f71558dcbb6c2e028fc5c7cf67270ef6fafd9cc865570b73700d405b2c2ebc02",
        "sha256:c270e2480dbc55f98c9730dd65b6df575be7d51a35a4057e9588f0dff7dd1bd3",
    ): "https://download.docker.com/linux/static/stable/x86_64/docker-29.10.1.tgz#061642059fa7f2ed9b2f04a327a951cff4249585cf04b2661c2a6539197c9962/docker/docker",
    (
        "usr/local/bin/docker-ensure-initdb.sh",
        "922ade6b23a312e65023349b36e873752b15ff38ae4c0ae461d74451e104f312",
        "sha256:347a7fa9ed7231add53985b20f81720093f18aa9729130a418b96c22682d40de",
    ): "https://github.com/docker-library/postgres/blob/ac9627dcf544a8454f212a12ddeebfcdc0803d3e/15/alpine3.23/docker-ensure-initdb.sh",
    (
        "usr/local/bin/docker-ensure-initdb.sh",
        "922ade6b23a312e65023349b36e873752b15ff38ae4c0ae461d74451e104f312",
        "sha256:f5e975d661d7f5f28eed5fb0d019fad8adf14789168c029a65c9da779e518835",
    ): "https://github.com/docker-library/postgres/blob/2603e26e245e558218728ee14e0a42dcb020dc7f/14/alpine3.23/docker-ensure-initdb.sh",
    (
        "usr/local/bin/docker-entrypoint.sh",
        "48647812e68165e2943abe82a1a7cb8364d6e9f8b6b6aefc179868b66a327c46",
        "sha256:347a7fa9ed7231add53985b20f81720093f18aa9729130a418b96c22682d40de",
    ): "https://github.com/docker-library/postgres/blob/ac9627dcf544a8454f212a12ddeebfcdc0803d3e/15/alpine3.23/docker-entrypoint.sh",
    (
        "usr/local/bin/docker-entrypoint.sh",
        "9c440299ae04a0a79d55b8bf03307036d890a40979d2fb698073c9050d4b20a5",
        "sha256:f5e975d661d7f5f28eed5fb0d019fad8adf14789168c029a65c9da779e518835",
    ): "https://github.com/docker-library/postgres/blob/2603e26e245e558218728ee14e0a42dcb020dc7f/14/alpine3.23/docker-entrypoint.sh",
    (
        "usr/local/bin/docker-entrypoint.sh",
        "f193a9318eb063138648c164cd66d1808dcf2cb9ead72c3d799eac2f0ea8d41d",
        "sha256:1f74bdd6b59620a5bd72f8f06ad1c4003106bc2ac509f648644293716923c779",
    ): "https://github.com/docker-library/docker/blob/5582709f55958f4485de248399d2a4b6129450ea/29/cli/docker-entrypoint.sh",
    (
        "usr/local/bin/docker-init",
        "31b005e7546cdbb9ec1a376cb064569113da2a9410fb1f2aaf8a3b2427765b7c",
        "sha256:fdf62cd757ced966ec0323b1833d18f93a1e6617705d825d43af900dfd662910",
    ): "https://download.docker.com/linux/static/stable/x86_64/docker-29.10.1.tgz#061642059fa7f2ed9b2f04a327a951cff4249585cf04b2661c2a6539197c9962/docker/docker-init",
    (
        "usr/local/bin/docker-proxy",
        "136544fc08bbf49e7d485b9435f41038bd89a3f9f37111b22bc6522c47ce17ab",
        "sha256:fdf62cd757ced966ec0323b1833d18f93a1e6617705d825d43af900dfd662910",
    ): "https://download.docker.com/linux/static/stable/x86_64/docker-29.10.1.tgz#061642059fa7f2ed9b2f04a327a951cff4249585cf04b2661c2a6539197c9962/docker/docker-proxy",
    (
        "usr/local/bin/dockerd",
        "5d758c2b8fbe38313f9c15bb124cc1101719dc7521771e9e3745846e18a0c126",
        "sha256:fdf62cd757ced966ec0323b1833d18f93a1e6617705d825d43af900dfd662910",
    ): "https://download.docker.com/linux/static/stable/x86_64/docker-29.10.1.tgz#061642059fa7f2ed9b2f04a327a951cff4249585cf04b2661c2a6539197c9962/docker/dockerd",
    (
        "usr/local/bin/dockerd-entrypoint.sh",
        "aa54301f80357bfca57112586d5ab08c512900500ec9be6fca64e4f0a6286e17",
        "sha256:5147b33e9fa191a1070cb605766a209d8f91711fde486db6a31c11acb9d5f817",
    ): "https://github.com/docker-library/docker/blob/5582709f55958f4485de248399d2a4b6129450ea/29/dind/dockerd-entrypoint.sh",
    (
        "usr/local/bin/idle3.13",
        "ed364e76d6a2ee3dc8e61a724b7d0c6e92d53c2b410e82e214a1e0444a0e2fa8",
        "sha256:2ed7a1a27c6d053227e15859d704914451dfa1f77792489b54ecc64103fe9db7",
    ): "https://github.com/docker-library/python/blob/152874b138f0b1c4699fbdcb52b174608cfbfff5/3.13/slim-bookworm/Dockerfile#L120",
    (
        "usr/local/bin/modprobe",
        "d448b121929c7e06253a0f5400b5b4d73f9f3862f052fd9999f5209994805d1e",
        "sha256:f2b983fa9c9f0de70add4d7b2a0d1667c20739fc7e86c79a20ed46e35bd19914",
    ): "https://github.com/docker-library/docker/blob/5582709f55958f4485de248399d2a4b6129450ea/29/cli/modprobe.sh",
    (
        "usr/local/bin/pydoc3.13",
        "2f1d379c20d1ea55d498dc93d87db17253d66427f50db1f84cfaef090d80e338",
        "sha256:2ed7a1a27c6d053227e15859d704914451dfa1f77792489b54ecc64103fe9db7",
    ): "https://github.com/docker-library/python/blob/152874b138f0b1c4699fbdcb52b174608cfbfff5/3.13/slim-bookworm/Dockerfile#L120",
    (
        "usr/local/bin/runc",
        "dbe0864ec684fed2aa408de200f76db14266dc4ce7b55accb7367da539c8c895",
        "sha256:fdf62cd757ced966ec0323b1833d18f93a1e6617705d825d43af900dfd662910",
    ): "https://download.docker.com/linux/static/stable/x86_64/docker-29.10.1.tgz#061642059fa7f2ed9b2f04a327a951cff4249585cf04b2661c2a6539197c9962/docker/runc",
    (
        "usr/local/lib/libpython3.so",
        "7c640c0121665d9a29b807d5968645278f6698a72533693e005a4e45baa5f8a3",
        "sha256:2ed7a1a27c6d053227e15859d704914451dfa1f77792489b54ecc64103fe9db7",
    ): "https://github.com/docker-library/python/blob/152874b138f0b1c4699fbdcb52b174608cfbfff5/3.13/slim-bookworm/Dockerfile#L120",
    (
        "usr/sbin/policy-rc.d",
        "21a8dca0d6a52cbac52cb7a86178d973616ffb42ea08747e6ff311659ab095e1",
        "sha256:3c5439d0ae62993af4cc4e21b8c777297e81bc40e200d4633c85a3e0f977a3bc",
    ): "https://github.com/debuerreotype/debuerreotype/blob/e63dab169190cd9403d77c6a87469fa0f153b659/scripts/debuerreotype-minimizing-config",
}


def upstream_origin(row):
    return _UPSTREAM_FILES.get((row["path"], row["sha256"], row["layer"]))


# docker-library/postgres pins the upstream source tar and runs install-world-bin.
_POSTGRES_BUILDS = {
    "sha256:e4cb93687b062cd25a0e8f672d85a7708235009d70d31f8a7698d9370092a9c4": (
        'sha256:694a01b64034f0992326512adbafc93dd0b318fde13b91ba7b59f3af999cb169',
        '17.11',
        'dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979',
        133,
        'b5c1612b28553e9277a21cf94696834690e6371fe5989235280c6443c1fcadcb',
    ),
    "sha256:e80acae3f1109e8e4533618b594918936f2858c63afc7204c4773148a673add8": (
        'sha256:c795bf66a3835e3c59c5ff9fc5b4c8cab99536920a5aaf8bc03ed7caaf380d48',
        '17.12',
        '9cf136a703d8ee2f83465c43be4e9e8e7930c82b0bfba13be7e2537be769ac55',
        133,
        'a7ed09e8f0a0ae37dc5fdbca10dc9de8d872759fd3931c9fca5a50becf3167cc',
    ),
}


def postgres_source(manifest, software):
    profile = _POSTGRES_BUILDS.get(manifest)
    if profile is None:
        return None
    layer, version, source_hash, count, expected = profile
    rows = sorted((r["path"], r["bytes"], r["sha256"]) for r in software if r["layer"] == layer
                  and r["path"].startswith(("usr/local/lib/", "usr/local/bin/")))
    if len(rows) != count or hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest() != expected:
        return None
    return version, dict(source_archive_sha256=source_hash, installed_members_sha256=expected,
                         layer=layer, manifest=manifest), [r[0] for r in rows]
