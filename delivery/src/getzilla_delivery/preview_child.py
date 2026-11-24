"""Trusted static-only child. Artifact bytes are data and never executed."""
from __future__ import annotations

import base64
import json
import os
import resource
import signal
import socket
import stat
import struct
import sys
import time
from pathlib import Path

# -I excludes cwd and environment paths. Resolve only the reviewed source tree.
SOURCE = Path(__file__).resolve()
sys.path.insert(0, str(SOURCE.parents[1]))
sys.path.insert(0, str(SOURCE.parents[3] / '.getzilla'))
from getzilla_delivery.local_preview import check_binding, read_state, runtime_digest, write_state
from getzilla_delivery.preview_contracts import LIMITS, PreviewError, PreviewManifest, artifact
from getzilla_delivery.preview_kernel import restrict_ip_sockets


def main():
    raw = sys.stdin.buffer.read(3 * 1024 * 1024 + 65537)
    if len(raw) > 3 * 1024 * 1024 + 65536:
        return 2
    config = json.loads(raw)
    manifest = PreviewManifest(**config['manifest'])
    manifest.validate()
    files, identity = artifact({k: base64.b64decode(v, validate=True) for k, v in config['files'].items()})
    if identity != manifest.artifact_digest or runtime_digest() != manifest.runtime_digest:
        return 2
    root, fd = Path(config['root']), config['directory_fd']
    lease = config['lease_fd']  # Keep the inherited project-wide flock until exit.
    os.fstat(lease)
    check_binding(root, manifest)
    deadline = config['deadline']
    if deadline <= time.monotonic():
        return 2
    # Trusted code only. No external executable, build, template, JS or user code.
    resource.setrlimit(resource.RLIMIT_CPU, (LIMITS['cpu_seconds'], LIMITS['cpu_seconds']))
    resource.setrlimit(resource.RLIMIT_AS, (LIMITS['memory_bytes'], LIMITS['memory_bytes']))
    resource.setrlimit(resource.RLIMIT_NOFILE, (LIMITS['descriptors'], LIMITS['descriptors']))
    # Evidence writes need a small finite size; stdout/stderr remain /dev/null.
    resource.setrlimit(resource.RLIMIT_FSIZE, (16384, 16384))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    reason, stopping = 'failed', False

    def stop(_number, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    egress_probe = restrict_ip_sockets()
    listener = socket.socket(socket.AF_UNIX)
    socket_identity = None
    requests, served = 0, 0
    observation = read_state(fd)
    try:
        listener.bind(f'/proc/self/fd/{fd}/access.sock')
        os.chmod('access.sock', 0o600, dir_fd=fd)
        socket_identity = os.stat('access.sock', dir_fd=fd, follow_symlinks=False)
        listener.listen(1)
        listener.settimeout(.05)
        from getzilla.disposable_resources import _process_identity
        observation.update(state='ready', pid=os.getpid(), ready_at=time.time(),
                           process_identity=_process_identity(os.getpid()), egress_probe=egress_probe,
                           socket_identity=[socket_identity.st_dev, socket_identity.st_ino])
        write_state(fd, observation)
        reason = 'expired'
        while not stopping and time.monotonic() < deadline:
            try:
                check_binding(root, manifest, source=False)
            except (PreviewError, OSError, ValueError):
                reason = 'authority_revoked'
                break
            if requests >= LIMITS['requests'] or served >= LIMITS['served_bytes']:
                reason = 'quota_exhausted'
                break
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            with client:
                client.settimeout(min(LIMITS['io_seconds'], max(.001, deadline - time.monotonic())))
                _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != os.geteuid():
                    continue
                requests += 1
                try:
                    data = bytearray()
                    while b'\r\n\r\n' not in data and len(data) <= LIMITS['request_bytes']:
                        part = client.recv(min(256, LIMITS['request_bytes'] + 1 - len(data)))
                        if not part:
                            break
                        data.extend(part)
                    if len(data) > LIMITS['request_bytes'] or b'\r\n\r\n' not in data:
                        continue
                    # Bound and recheck after slow clients; no content after expiry.
                    if time.monotonic() >= deadline or stopping:
                        break
                    check_binding(root, manifest)
                    lines = bytes(data).split(b'\r\n')
                    binding = b'X-Preview-Binding: ' + manifest.identity.encode()
                    if lines.count(binding) != 1:
                        client.sendall(b'HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                        continue
                    if lines[0] == b'POST /revoke HTTP/1.0':
                        reason, stopping = 'revoked', True
                        client.sendall(b'HTTP/1.0 204 No Content\r\nContent-Length: 0\r\n\r\n')
                        continue
                    pieces = lines[0].split(b' ')
                    if len(pieces) != 3 or pieces[0] != b'GET' or pieces[2] != b'HTTP/1.0':
                        continue
                    path = pieces[1].decode('ascii')
                    name = 'index.html' if path == '/' else path[1:]
                    body = files.get(name) if path.startswith('/') else None
                    status = 200 if body is not None else 404
                    body = body or b''
                    if served + len(body) > LIMITS['served_bytes']:
                        reason, stopping = 'quota_exhausted', True
                        continue
                    mime = ('text/html' if name.endswith('.html') else 'text/css' if name.endswith('.css')
                            else 'image/png' if name.endswith('.png') else 'application/octet-stream')
                    headers = (f'HTTP/1.0 {status} Response\r\nContent-Length: {len(body)}\r\n'
                               f'Content-Type: {mime}\r\nCache-Control: no-store\r\n'
                               "Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; sandbox\r\n"
                               'X-Content-Type-Options: nosniff\r\n\r\n').encode()
                    client.sendall(headers + body)
                    served += len(body)
                except (OSError, UnicodeError, ValueError):
                    continue
        if stopping and reason == 'expired':
            reason = 'cancelled'
    finally:
        listener.close()
        cleanup = 'unconfirmed'
        try:
            current = os.stat('access.sock', dir_fd=fd, follow_symlinks=False)
            if (socket_identity is not None and stat.S_ISSOCK(current.st_mode)
                    and (current.st_dev, current.st_ino) == (socket_identity.st_dev, socket_identity.st_ino)):
                os.unlink('access.sock', dir_fd=fd)
                cleanup = 'confirmed'
        except FileNotFoundError:
            cleanup = 'confirmed'
        observation.update(state='destroying' if cleanup == 'confirmed' else 'unknown', reason=reason,
                           cleanup=cleanup, stopped_at=time.time(), requests=requests, served_bytes=served,
                           process_reaped=False)
        write_state(fd, observation)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
