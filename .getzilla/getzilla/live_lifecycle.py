"""One hundred measured Docker lifecycles, including verifier cancellation.

This exercises the CI disposable-resource path. Factory workspace and remote
asset retention are separate obligations; no claim about them is made here.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

from .disposable_resources import OwnedDocker, image_pins
from .python_test_runner import RunCancelled, execute


def _run(*args, timeout=30):
    return subprocess.run(["docker", *args], check=True, capture_output=True,
                          text=True, encoding="utf-8", timeout=timeout).stdout.strip()


def _write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)


def inventory():
    return {"containers": sorted(_run("container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}").splitlines()),
            "volumes": sorted(_run("volume", "ls", "--format", "{{.Name}}").splitlines()),
            "networks": sorted(_run("network", "ls", "--no-trunc", "--format", "{{.ID}}").splitlines())}


def cycles_accepted(rows):
    if not (len(rows) == 100 and [row.get("cycle") for row in rows] == list(range(1, 101))
            and all(row.get("status") == "pass" and row.get("disposable_remaining") == 0
                    and row.get("protected_unchanged") is True and row.get("payload_bytes") == 1024
                    and row.get("directory_payload_bytes") == 1024 for row in rows)):
        return False
    seen = set()
    for row in rows:
        resources = row.get("resources", [])
        if (len(resources) != 4 or {item.get("kind") for item in resources} != {"container", "volume", "network", "directory"}
                or any(not re.fullmatch(r"gz-[a-z0-9-]+", item.get("name", "")) for item in resources)):
            return False
        container = next(item for item in resources if item["kind"] == "container")
        identifier = container.get("id", "")
        if not re.fullmatch(r"[0-9a-f]{64}", identifier) or identifier in seen:
            return False
        seen.add(identifier)
    return True


def _allocate(root, owner):
    pin = image_pins(root)["python"]
    directory = owner.directory("directory")
    (directory / "payload").write_bytes(b"x" * 1024)
    volume = owner.volume("data")
    network = owner.network("network")
    container = owner.container("worker", pin["reference"], volume=volume, volume_target="/data", network=network,
                                 command=("python3", "-c", "import time; time.sleep(600)"))
    if container["image_id"] != pin["image_id"]:
        raise RuntimeError("Lifecycle image configuration does not match its pinned manifest")
    _run("exec", container["id"], "python3", "-c", "from pathlib import Path; Path('/data/payload').write_bytes(b'x'*1024)")
    measured = int(_run("exec", container["id"], "python3", "-c", "from pathlib import Path; print(Path('/data/payload').stat().st_size)"))
    if measured != 1024:
        raise RuntimeError("Lifecycle payload measurement failed")
    return container, {"payload_bytes": measured, "directory_payload_bytes": (directory / "payload").stat().st_size,
                       "resources": [{key: item[key] for key in ("kind", "name", "id") if key in item} for item in owner.resources]}


def _protected(container):
    metadata = json.loads(_run("container", "inspect", container["id"]))[0]
    payload = _run("exec", container["id"], "python3", "-c", "from pathlib import Path; import hashlib; print(hashlib.sha256(Path('/data/payload').read_bytes()).hexdigest())")
    return {"id": metadata["Id"], "labels": metadata["Config"]["Labels"], "payload_sha256": payload}


def worker(root, output, namespace, mode):
    owner = OwnedDocker(output / (namespace + "-resources.json"), namespace)
    def cancelled(_number, _frame):
        raise KeyboardInterrupt()
    previous_handler = signal.signal(signal.SIGTERM, cancelled)
    primary, code = None, 0
    cleanup_status = "not_run"
    try:
        _container, sample = _allocate(root, owner)
        _write(output / (namespace + "-sample.json"), sample)
        (output / (namespace + "-ready")).touch()
        if mode == "kill":
            os.kill(os.getpid(), signal.SIGKILL)
        if mode == "failure":
            code = 23
        else:
            while True:
                time.sleep(.05)
    except KeyboardInterrupt as exc:
        primary, code = exc, 130
    except BaseException as exc:
        primary, code = exc, 1
    finally:
        try:
            owner.cleanup()
            cleanup_status = "removed"
        except BaseException as cleanup:
            cleanup_status = "unconfirmed"
            if primary is None and code == 0:
                primary, code = cleanup, 1
            elif primary is not None:
                primary.add_note("Worker cleanup unconfirmed: " + type(cleanup).__name__)
        try:
            _write(output / (namespace + "-ack.json"), {"cleanup": cleanup_status,
                "allocator_pid": os.getpid(), "primary_exit": code,
                "primary_error": type(primary).__name__ if primary else None})
        except OSError as acknowledgement:
            if code == 0:
                code = 1
            if primary is not None:
                primary.add_note("Cleanup acknowledgement unavailable: " + type(acknowledgement).__name__)
        finally:
            signal.signal(signal.SIGTERM, previous_handler)
    return code


def _child_cycle(root, output, namespace, mode):
    command = [sys.executable, str(root / "scripts/getzilla_live_lifecycle.py"), "--root", str(root),
               "--output", str(output), "--namespace", namespace, "--mode", mode]
    timer_done = threading.Event()
    signal_sent = []
    requested = signal.SIGINT if mode == "sigint" else signal.SIGTERM
    def signal_when_bound():
        deadline = time.monotonic() + 30
        while not timer_done.is_set() and time.monotonic() < deadline:
            if (output / (namespace + "-ready")).is_file():
                signal_sent.append(int(requested))
                os.kill(os.getpid(), requested)
                return
            timer_done.wait(.05)
    timer = None
    if mode in ("sigint", "sigterm"):
        timer = threading.Thread(target=signal_when_bound, daemon=True)
        timer.start()
    cancellation = None
    try:
        try:
            result = execute(command, root, dict(os.environ), timeout=35 if mode == "timeout" else 45,
                             termination_grace=120)
        except RunCancelled as exc:
            cancellation = exc.signal_number
            result = exc.result
    finally:
        timer_done.set()
        if timer:
            timer.join(timeout=1)
    if result is None or result.cleanup_error:
        raise RuntimeError("Lifecycle child exit was not confirmed")
    journal = output / (namespace + "-resources.json")
    if mode == "kill":
        if result.returncode != -signal.SIGKILL:
            raise RuntimeError("Abrupt death fixture did not die after binding")
        # A new process, not an in-memory instance of the old allocator, reconciles it.
        subprocess.run([sys.executable, str(root / "scripts/getzilla_live_lifecycle.py"),
                        "--recover", str(journal)], check=True, timeout=150)
        cleanup_kind = "observer_recovery"
    else:
        expected = 23 if mode == "failure" else 124 if mode == "timeout" else 130
        if mode in ("sigint", "sigterm"):
            if cancellation != requested or signal_sent != [int(requested)]:
                raise RuntimeError("Verifier did not observe the requested cancellation")
        elif result.returncode != expected:
            raise RuntimeError("Primary failure or timeout was lost")
        if json.loads((output / (namespace + "-ack.json")).read_text(encoding="utf-8")).get("cleanup") != "removed":
            raise RuntimeError("Native cleanup acknowledgement is absent")
        cleanup_kind = "native_acknowledged"
    owner = OwnedDocker.recover(journal)
    owner.cleanup()
    if owner.cleanup_status != "removed":
        raise RuntimeError("Lifecycle cleanup readback failed")
    sample = json.loads((output / (namespace + "-sample.json")).read_text(encoding="utf-8"))
    return {**sample, "mode": mode, "cleanup_kind": cleanup_kind,
            "child_returncode": result.returncode, "cancellation": cancellation,
            "disposable_remaining": sum(item["status"] != "removed" for item in owner.resources)}


def run(root, output, namespace):
    baseline = inventory()
    protected_file = output / "protected-evidence.txt"
    protected_file.write_bytes(b"lifecycle retained evidence\n")
    protected_digest = hashlib.sha256(protected_file.read_bytes()).hexdigest()
    foreign = OwnedDocker(output / "protected-resources.json", namespace + "-protected")
    rows = []
    primary = None
    started = time.monotonic()
    try:
        sentinel, _sample = _allocate(root, foreign)
        protected = _protected(sentinel)
        concurrent_baseline = inventory()
        for number in range(1, 101):
            if time.monotonic() - started > 840:
                raise TimeoutError("100-cycle main-phase deadline exceeded")
            cycle_namespace = namespace + f"-c{number}"
            mode = {96: "sigint", 97: "sigterm", 98: "failure", 99: "timeout", 100: "kill"}.get(number, "normal")
            if mode == "normal":
                owner = OwnedDocker(output / (cycle_namespace + "-resources.json"), cycle_namespace)
                cycle_error = None
                try:
                    container, sample = _allocate(root, owner)
                    if number % 10 == 0:
                        previous = json.loads(_run("container", "inspect", container["id"]))[0]["State"]["StartedAt"]
                        _run("restart", container["id"], timeout=45)
                        observed = json.loads(_run("container", "inspect", container["id"]))[0]["State"]["StartedAt"]
                        if previous == observed:
                            raise RuntimeError("Lifecycle restart did not replace the running process")
                        sample["restart"] = {"before": previous, "after": observed}
                except BaseException as exc:
                    cycle_error = exc
                    raise
                finally:
                    try:
                        owner.cleanup()
                    except BaseException as cleanup:
                        if cycle_error is None:
                            raise
                        cycle_error.add_note("Cycle cleanup unconfirmed: " + type(cleanup).__name__)
                owner.cleanup()  # at-least-once finalization must preserve other runs
                row = {**sample, "mode": mode, "cleanup_kind": "native",
                       "disposable_remaining": sum(item["status"] != "removed" for item in owner.resources)}
            else:
                row = _child_cycle(root, output, cycle_namespace, mode)
            preserved = (_protected(sentinel) == protected
                         and hashlib.sha256(protected_file.read_bytes()).hexdigest() == protected_digest
                         and inventory() == concurrent_baseline)
            row.update(cycle=number, protected_unchanged=preserved, status="pass" if preserved else "fail")
            rows.append(row)
            if not preserved:
                raise RuntimeError("Cleanup changed another active run or protected evidence")
        if not cycles_accepted(rows):
            raise RuntimeError("The measured lifecycle evidence does not satisfy all 100 cycles")
    except BaseException as exc:
        primary = exc
    cleanup_error = None
    try:
        foreign.cleanup()
    except BaseException as exc:
        cleanup_error = exc
        if primary is None:
            primary = exc
        else:
            primary.add_note("Protected fixture cleanup: " + type(exc).__name__)
    after = None
    try:
        after = inventory()
    except BaseException as exc:
        if primary is None:
            primary = exc
        else:
            primary.add_note("Final resource inventory unavailable: " + type(exc).__name__)
    passed = primary is None and cycles_accepted(rows) and baseline == after
    _write(output / "lifecycle.json", {"check_id": "factory-lifecycle", "cycles": rows,
        "status": "pass" if passed else "fail", "resources_before": baseline, "resources_after": after,
        "primary_error": type(primary).__name__ if primary else None,
        "cleanup_error": type(cleanup_error).__name__ if cleanup_error else None,
        "bytes_definition": "Measured payload bytes; removed volume/directory identities imply zero remaining owned payload. Shared image layers excluded.",
        "scope": "Disposable CI containers, volumes, networks, bounded payload directories; no remote assets or Factory workspace claim"})
    if primary is not None:
        raise primary
    if not passed:
        raise RuntimeError("Disposable resource inventory did not return to baseline")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--namespace")
    parser.add_argument("--mode", choices=("sigint", "sigterm", "failure", "timeout", "kill"))
    parser.add_argument("--recover", type=Path)
    args = parser.parse_args(argv)
    if args.recover:
        owner = OwnedDocker.recover(args.recover)
        owner.cleanup()
        return 0
    if args.root is None or args.output is None or args.namespace is None or args.mode is None:
        parser.error("worker arguments are required")
    return worker(args.root, args.output, args.namespace, args.mode)
