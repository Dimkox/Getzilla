# Architecture diagnostics lost the last active phase

A targeted architecture observation on `cb291f9926adc97ccd2313ab94c28eea2745cca9`
ended at its 180-second diagnostic bound with exit 124 and empty stdout/stderr.
This did not establish a failed predicate or a product execution deadline. The
performance cause and terminal fitness results remained unknown.

The standalone CLI did not open the existing verification journal, and inner
source/demand work had no checkpoints. Repeating an observation without those
boundaries could not identify where it stopped.

Reuse the run-owned rotating journal at the CLI boundary. Emit phase and source
checkpoints before work, retain a bounded validated active span in actor health,
and keep locations or reconstructable hashes instead of source or error text.
Rotation and an ordinary process stop must leave an incomplete observation with
a useful last active pointer. Missing terminal results never establish success.
Owned controls cover inactive library calls, clean JSON stdout, actual phase
wiring, privacy, rotation and an abruptly stopped child. Analyzer limits and
qualification requirements are unchanged.
