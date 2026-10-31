# GH287: inherited target state in command compositions

Independent security review of commit `02abd29fede034d2436577d53d9f74dbcffa3b81` found that a command before a granted write could replace an inherited target. Direct policy and full-hook checks both admitted four negative controls. The review remains a failure for that commit.

The collector treated a known data-argument command family as neutral. It also checked only selected state-writer names and target variable spellings. That missed variable destinations, default destinations, indirect references and evaluated printf operands. Earlier tests proved command-local assignments but did not cover inherited exported targets changed by builtins.

The repair requires a closed neutral command and option proof around a mutation. Printf admits literal text, simple literal escapes, `%%` and `%s`; its data operands retain their roles. Explicit Git and GH read forms remain usable. The existing literal same-root `cd` and `pushd` forms remain supported. Stack selection and unknown directory options stay unresolved. Unknown state writers, dispatchers, assignments, read-family options and prefix redirections remain unresolved. Unproved context propagates through the admitted shell payload even when that payload contains no recognized mutation. The existing root and grant boundaries stay in force.

The same batch restores the confirmed Linux curl regression. The collector now consumes `--noproxy` as an option value. Existing tests continue to deny secret reads through request bodies and headers. Active shell expansion remains outside mutation admission.

Tests cover the four independent failures at both policy and full-hook layers, the bounded stateful families, literal data positives, command-local environment, read subcommand and option boundaries, and the unchanged curl regressions. Raw commands and intermediate failures stay in private runtime evidence. Independent review and the final qualifying gate belong to the coordinator.

## Rework after the option-arity review

Independent review of the same tree at `e359dcafb684136475007f19724cdf6db3fc4038` found that the Git proof gave optional or attached-only format options the wrong arity. A bare format option could hide an active file-output option from the policy. The previous tests checked known option names but did not compare their argument roles with the installed CLI.

The repair separates required next-word values from attached-only values. Optional attached values admit their bare spelling as a flag; mandatory attached values refuse the bare spelling. The current Git option inventory was audited. Tests preserve format data that resembles options and deny active output options at both policy and full-hook layers with valid grants. Bounded installed-Git controls write only new public fixture files. They distinguish successful bare-pretty output from bare-format failure after empty-file creation. Protected configuration remains unchanged, and no GH or network command executes.

## Rework after the API hostname review

Independent code and security reviews of `d55cba8b8107815a8a63f741dd319ce3a0672c13` found that the role-aware argument parser admitted an API hostname selector before the subcommand, but resource extraction read only the suffix. Both API writes and API merges could therefore use a grant for the default host while selecting another host. Direct policy and full-hook probes confirmed the mismatch. Offline help parsing with the official GitHub CLI confirmed that the prefix syntax is supported.

Both resource paths now take the selected host from the complete role-aware invocation before interpreting the API suffix. The explicit endpoint URL still determines its own authority. Regression tests cover separated and attached selectors on both sides of the subcommand, explicit selection over inherited host state, wrong-host denials, correct-host admission, both required API merge scopes, and duplicate selector rejection. Existing literal-field controls remain in force. The new negative controls failed before the repair; no remote API operation or credential read was used to reproduce the defect.
