# Agent eval baseline and report boundary defects

Independent review found three defects in the first issue #305 candidate
`2a049cfd986c7313d520131c2babf87662a37054`. No merge or deployment was claimed.

Baseline operations checked parent paths, then opened those paths again. A
concurrent ancestor replacement could redirect reads and acceptance writes.
The repair retains every directory descriptor, validates current names and
file identities, and performs lock, read, temporary-file, replacement and
cleanup operations relative to those descriptors. Unsupported platforms refuse
baseline operations. Missing parents remain absent.

Numeric telemetry used `math.isfinite` before bounding arbitrary JSON integers.
Very large integer latency and confidence values raised `OverflowError`.
The repair applies numeric bounds first and returns bounded invalid evidence.

The report cap covered replay before comparison. Adding paired baseline evidence
could exceed the export limit. The repair caps the complete exported envelope
and returns an invalid/inconclusive refusal when it cannot retain the evidence.

Regression controls reproduced each defect before repair. They also cover
concurrent destination changes, lock ownership, publication-time directory
replacement, numeric boundary values and a real 100-case export.
