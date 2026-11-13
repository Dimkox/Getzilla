# Generated Factory metadata differed between payload and test inputs

The initial #412 regression checked the installer payload alone. Factory source
inventory still included the six generated files that the repaired installer
excluded. The later full local run failed the bound-input payload assertion and
returned exit124 without final test counts; that exit does not establish its
underlying stop cause.

A new tiny Git-free fixture confirmed the membership mismatch. Apply the same
exact real-directory exclusion to both consumers, after symlink rejection. Keep
regular files, nested and similarly named assets, and special-file refusals intact.
The regression now compares both consumers before and after metadata generation.
