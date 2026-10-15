"""One host logical-CPU reserve, then process and cgroup limits."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import os
import sys

from ._cpu_capacity import linux_quota_capacity


@dataclass(frozen=True)
class CpuBudget:
    host_logical: int
    reserve: int
    requested: int
    available: int
    quota: int | None
    effective: int
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def cpu_budget(requested: int | None = None) -> CpuBudget:
    """Never widen affinity; sched_getaffinity already intersects online/cpuset.

    Missing affinity evidence is conservatively one worker. Reserve two from
    the HOST logical count exactly once, not from the restricted child count.
    Explicit allocations can reduce the budget but cannot remove its reserve.
    """
    if requested is not None and (type(requested) is not int or requested <= 0):
        raise ValueError('CPU allocation must be a positive integer')
    host = os.cpu_count() or 1
    limit = max(1, host - 2)
    wanted = limit if requested is None else requested
    reasons = ['host-reserve-two']
    try:
        available = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        available = 1
        reasons.append('affinity-unknown')
    if available <= 0:
        raise ValueError('no allowed online CPU')
    quota = linux_quota_capacity() if sys.platform == 'linux' else None
    selected = min(wanted, limit, available, quota if quota is not None else limit)
    if available < min(wanted, limit):
        reasons.append('affinity-cpuset')
    if quota is not None and quota < min(wanted, limit, available):
        reasons.append('cgroup-quota')
    return CpuBudget(host, min(2, max(0, host - 1)), wanted, available, quota, selected, tuple(reasons))
