# Inherited source modes blocked installed input validation

The first local qualification of `02e3d768` failed. Its immutable report
`219305063e156c2fde4957f7b443a2dac64b90236dc2252456967475ae84c303`
records Core output-limit termination after 713.726 seconds, unqualified
coverage, Factory failures and aggregate-source refusals. External checks
and scoped reviews passed; they did not replace that failed local result.

Finite custody checks found 521 committed baseline blobs with correct bytes
but inherited mode `0664`, where the installed resource/disposition format
requires `0644`. Preparing only the 11 changed files missed these inputs.
Root preserved the failed artifacts, then admitted and prepared 6,728 exact
Git-identical owned files in the isolated checkout. All postchecks passed;
16 excluded entries stayed untouched. File descriptors closed and source
HEAD, tree and fingerprint stayed unchanged.

The missing environment check was the process error. Validate the finite
owned source inputs before qualification, including installed baseline blobs.
Prepare only admitted standard modes with unchanged Git bytes. Do not infer
that this explains every failure, retry an unchanged failed head, or change
its historical verdict. Other causes remain unproved. The source-boundary
repair requires fresh whole-source qualification.
