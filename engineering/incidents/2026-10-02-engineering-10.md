<!-- Historical source: 01f67873ea17949208f92c83d34d0af38a586779:engineering/mistakes.md; bytes 411:840; sha256 cc78ac56afe2f82097e10cc2fc843a2918e500eec69937d2fc84c238594dad67. -->

## 2026-10-02 — Reused a known nonstandard help trap

Root cause: I assumed `run_disposable_exit.py --help` behaved like a conventional argparse
entrypoint instead of consulting the existing mistake record or reading its source; the script
ignores that argument and starts the full suite. Keep the one live run, never duplicate it, and
inspect source before probing repository harnesses whose CLI behavior was already learned.


Source: [engineering/mistakes.md:10-15](https://github.com/Dimkox/getzilla/blob/01f67873ea17949208f92c83d34d0af38a586779/engineering/mistakes.md#L10-L15).

No pull request association is asserted by this archive.
