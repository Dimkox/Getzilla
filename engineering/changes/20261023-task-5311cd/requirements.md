# Requirements

Typed authority: change-spec.yaml.

- Reject a controller missing os.pidfd_open or signal.pidfd_send_signal before spawn.
- Preserve supported-host start, stop, recovery and process identity behavior.
- Validate the current wheel inventory against factory/uv.lock.
- Run clean committed smoke, independent code/test/security/release reviews and one final full PR gate.
- Require exact-head public CI and resolved PR threads before merge.

No schema, API, dependency, deployed policy or production change is in scope. Low findings in issues #122 and #134 remain deferred to their shared follow-up.

The exact-diff risk check selected release review in addition to code, test and security. These reviews cover source readiness and revisit PR127 audit boundaries. This successor does not publish a release.
