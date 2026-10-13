# lock bounded design

Route07e734b12522; HEAD6dd06ff5b96692a01812fbac6252fd08f6169f91. Read-only design.
- Own committed trust-ci lock, three Docker consumers, public CI install consumer and binding tests. Include production and test extra resolution; keep direct pyproject declarations consistent.
- Lock must govern actual installation, not merely exist for scanning. Install pinned transitive set then local project without dependency re-resolution; cover isolated build-system pins too. Hash verification where chosen must bind all selected artifacts. Do not expand workflow permissions, secrets or deployed Trust CI policy.
- Existing Docker api/worker install dot; test installs test extra. Public Actions copies trust-ci source and installs test extra. Bind each to correct lock profile; ruff/bandit/tomli independent CI pins must retain explicit scope.
- RED remove a transitive pin or detach any consumer from lock; binding test must fail. Scanner must enumerate locked dependencies with manifest provenance. Check Python/platform markers and Windows/Linux selected sets; one-host lock cannot silently exclude supported platform dependencies.
- Review source dependency change and package builds; no deployed service/image update. Offline caches may be used. Resolver outputs are evidence only until committed exact pins. No leaf full gate.

No candidate edits or tests ran. reviewed-tree-modified: no
