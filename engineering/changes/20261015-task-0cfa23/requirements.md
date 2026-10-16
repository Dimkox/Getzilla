# Requirements — GZ-HOOK-ROOT-001

> Typed authority: [change-spec.yaml](change-spec.yaml).

- Quoted and escaped pipe, semicolon and parenthesis characters remain argument data. The exact gh/jq reproduction, rg alternation, jq functions and quoted grant reasons reach normal policy checks.
- Actual pipes, semicolons, subshells, background operators, active substitutions, malformed quotes and unsupported wrappers remain denied. Supported bounded `&&` and newline chains retain their existing contract.
- Literal operator words do not become separate commands. `bash -c`, Python inline programs and PowerShell command arguments retain the existing code and write analysis.
- Explicit workdirs and isolated worktrees work for reads. Conflicting root aliases and cross-worktree grants still fail closed for sensitive actions. Existing soft behavior for non-sensitive reads with unresolved roots is unchanged.
- Denial records separate hook source identity from session and effective roots. They include digest and source-field names without raw argument or environment values. Retry counts, fingerprints, expiry and decisions stay unchanged.

No dependency, network call, external mutation, runtime migration or public API is added. The internal lexical scan is linear in command length. Existing command-size and nesting bounds remain in force. `env` wrappers remain unsupported by root inference. Dynamic authority selectors keep the separate conservative guard.

Governance: preserve the existing route-policy no-network boundary. No new architecture edge or policy exception is required.
