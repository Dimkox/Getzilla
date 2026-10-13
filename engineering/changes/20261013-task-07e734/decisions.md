# Decision

Use frozen uv exports with existing pip consumers; no uv image/runtime dependency is needed. The stdlib checker derives complete graph closure and hashes from the lock, so duplicated profiles cannot silently drift.
