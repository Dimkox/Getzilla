# Hook launchers on Windows and POSIX

Generated launchers select a usable Python interpreter before running a hook.
A hook runs once. Its stdout, stderr, JSON input and exit status pass through,
including a policy denial with status 2. A denial never triggers a Python fallback.
Windows uses stock `powershell.exe` with an encoded PowerShell 5.1 command.
The selected Python process inherits the original standard handles, so the
launcher does not decode and encode JSON input through a PowerShell pipeline.

Source checkout adapters use `getzilla hook`. The existing installers add
Getzilla's `bin` directory to PATH on Windows and link the POSIX launcher into
`~/.local/bin`. Open a fresh terminal and restart the client after installation
or a PATH change. Check `getzilla hook --help` there before using source hooks.
Updating or activating the source checkout needs no platform-specific changes
to tracked adapter files. Rerender source adapters with
`getzilla harness --repository-all --write` after changing canonical inputs.

Consumer installs generate direct platform commands before the existing managed
file transaction. They do not require a global `getzilla` command. Owned update
and `getzilla harness --write` use the same rendering. CAS checks, kept files and
local edits retain their existing protections. Restart/review hooks in the client
after updating them; Getzilla does not grant client trust automatically.

The hook runner and the model's shell tool can use different shells:

- [Qwen](https://github.com/QwenLM/qwen-code/blob/main/packages/core/src/utils/shell-utils.ts)
  defaults to ComSpec/cmd on Windows, or Git Bash in an MSYS environment. Its
  manual PowerShell hook override does not propagate native exit 2 through
  `-Command`; that override is outside the supported default source contract.
- [Gemini's hook runner](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/hooks/hookRunner.ts)
  adds explicit exit-status propagation when it uses PowerShell. Its current
  shell selection prefers available pwsh and otherwise uses Windows PowerShell.
- [Codex](https://learn.chatgpt.com/docs/hooks) supports `commandWindows`.
  [Copilot](https://docs.github.com/en/copilot/reference/hooks-reference) supports
  separate `bash` and `powershell` commands. The generated adapters use them.
- [Grok's Windows shell runner](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-config/src/shell.rs)
  prefers pwsh, then Windows PowerShell. It does not add native exit-status
  propagation to `-Command`. Use its supported process-level `GROK_SHELL=cmd`
  before launching Grok when exact native hook status is required on Windows.
  The default PowerShell runner can map status 2 to 1. Getzilla does not silently
  change this client setting or claim default Grok status preservation.

Installing pwsh does not select the shell of an already running client or change
Qwen's cmd default. When a tool runs `powershell.exe`, use PowerShell 5.1 syntax.
Use PowerShell 7 operators such as `||` only when the client explicitly runs pwsh.
This launcher repair does not rewrite model commands or client shell settings.

Native Windows controls execute cmd and stock Windows PowerShell when available.
Linux runs explicitly skip those controls; Linux results do not prove native
Windows readiness or the behavior of an unobserved client version.
