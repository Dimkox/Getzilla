# GH287: inherited target state in command compositions

Independent security review of commit `02abd29fede034d2436577d53d9f74dbcffa3b81` found that a command before a granted write could replace an inherited target. Direct policy and full-hook checks both admitted four negative controls. The review remains a failure for that commit.

The collector treated a known data-argument command family as neutral. It also checked only selected state-writer names and target variable spellings. That missed variable destinations, default destinations, indirect references and evaluated printf operands. Earlier tests proved command-local assignments but did not cover inherited exported targets changed by builtins.

The repair requires a closed neutral command and option proof around a mutation. Printf admits literal text, simple literal escapes, `%%` and `%s`; its data operands retain their roles. Explicit Git and GH read forms remain usable. The existing literal same-root `cd` and `pushd` forms remain supported. Stack selection and unknown directory options stay unresolved. Unknown state writers, dispatchers, assignments, read-family options and prefix redirections remain unresolved. Unproved context propagates through the admitted shell payload even when that payload contains no recognized mutation. The existing root and grant boundaries stay in force.

The same batch restores the confirmed Linux curl regression. The collector now consumes `--noproxy` as an option value. Existing tests continue to deny secret reads through request bodies and headers. Active shell expansion remains outside mutation admission.

Tests cover the four independent failures at both policy and full-hook layers, the bounded stateful families, literal data positives, command-local environment, read subcommand and option boundaries, and the unchanged curl regressions. Raw commands and intermediate failures stay in private runtime evidence. Independent review and the final qualifying gate belong to the coordinator.
