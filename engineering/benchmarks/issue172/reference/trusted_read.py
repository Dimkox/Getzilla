"""Disposable benchmark reader. It is not an installed product boundary."""
import hashlib,os,pathlib,stat
def read_hit(root,hit,tenant,repository,allowed):
    if hit['tenant']!=tenant or hit['repository']!=repository:raise ValueError('partition')
    path=pathlib.PurePosixPath(hit['path'])
    if path.is_absolute() or '..' in path.parts or str(path)!=hit['path'] or str(path) not in allowed:raise ValueError('path')
    root=pathlib.Path(root).resolve(); candidate=root
    for part in path.parts:
        candidate=candidate/part
        if candidate.is_symlink():raise ValueError('symlink')
    try:
        if not candidate.resolve().is_relative_to(root):raise ValueError('escape')
        fd=os.open(candidate,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):raise ValueError('nonregular')
            data=f.read()
    except OSError as e:raise ValueError('missing') from e
    if hashlib.sha256(data).hexdigest()!=hit['file_sha256']:raise ValueError('stale')
    lines=data.splitlines(keepends=True);start=hit['start'];end=hit['end']
    if type(start)!=int or type(end)!=int or not 1<=start<=end<=len(lines):raise ValueError('range')
    chunk=b''.join(lines[start-1:end])
    if hashlib.sha256(chunk).hexdigest()!=hit['sha256']:raise ValueError('chunk')
    return chunk
