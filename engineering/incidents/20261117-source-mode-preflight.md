# Source mode precheck missed installed resources

The first qualifier for `9e9778cf` stopped at its output limit after 687
seconds. Its coverage is unqualified. The first historical exception and
all other causes remain unknown.

The coordinator changed the owned checkout root from `0775` to `0700`, but
missed its tracked resource modes. All 521 required baseline blobs had the
correct Git bytes and mode `0664`; the installer requires `0644`. This is a
sufficient static blocker, not proof that it caused every retained failure.
Clean Git status does not prove the full filesystem permission bits.

Create public checkout files with umask `022`. Before qualification, use
held file descriptors to check ownership, regular-file identity, link count,
Git bytes and required modes across the finite source inputs. Normalize only
proved owned files and preserve their bytes, including declared checkout
line endings. Keep runtime state private. Preserve the failed result and
require fresh qualification of the repaired candidate.
