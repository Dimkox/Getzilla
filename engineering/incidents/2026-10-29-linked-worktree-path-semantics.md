# Linked-worktree path semantics

Independent review of PR #244 found two defects in candidate ac7071c. The root check treated physical path resolution as equivalent to the shell's logical directory change. A path with a symbolic link and parent traversal could select different repositories. The registration check also compared raw Git output with a native path string, which differs in separator spelling on Windows. No push executed during the probes.

The repair requires the directory operand itself to match the canonical target path. It compares registered paths with native path semantics. Regressions cover the rejected directory spelling and Windows path equality, including different-drive and different-directory negatives. Linux focused tests pass. Native Windows execution remains a CI obligation.

Use the execution engine's path semantics at authorization boundaries. Test path spelling separately from filesystem identity. Do not treat a successful path resolution as proof of where a shell command will run.
