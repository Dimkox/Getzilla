# Exact architecture source fixtures

The optional `source_fixtures` architecture field admits one closed profile:
`c-public-elf-probe-v1`. It binds the exact public C probe and the complete
`tests/test_reverse_engineering.py` consumer by path, hash and verifier owner.
Both hashes also belong to the reviewed reader profile. A declaration cannot
choose new bytes or widen the supported language set.

The reviewed consumer compiles a shared ELF in an owned temporary directory with
a ten-second timeout, then inspects its bytes. It does not execute or load that
ELF. The profile validates source custody and this exact static relationship;
it does not run a compiler or issue native qualification evidence.

Missing, linked, oversized or changed source/consumer files refuse admission.
Other C/C++/header files remain unsupported, including files under tests. Changing
the probe or consumer requires explicit profile review. Fixtures remain in the
architecture inventory and fingerprints; the declaration grants no production
execution, external effects or policy exception. Actual compilation and addon
packaging checks retain their separate observed results and platform limits.
