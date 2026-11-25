import socket
import sys
from pathlib import Path


def job(gateway):
    if {p.name for p in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise ValueError('job has a network interface other than loopback')
    for host in ('127.0.0.1', gateway):
        for port in (2375, 2376):
            try:
                with socket.create_connection((host, port), timeout=2):
                    pass
            except OSError as exc:
                print(host, port, exc)
            else:
                raise ValueError('daemon TCP reachable from job')
    for path in ('/api/engine.sock', '/run/user/1000/docker.sock', '/var/run/docker.sock'):
        with socket.socket(socket.AF_UNIX) as client:
            try:
                client.connect(path)
            except OSError as exc:
                print(path, exc)
            else:
                raise ValueError('daemon socket reachable from job')


if __name__ == '__main__':
    job(sys.argv[1])
