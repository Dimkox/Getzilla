# Rollback

If the repair changes parent scope or unrelated child controls, stop and forward-fix the single environment filter. Before external delivery, return to the original local source commit 05f85f12b72b3a897c45c24e172fac8317120b7c in a separate checkout; preserve evidence and the old archive.

No data migration or production recovery is required. Re-run the child environment regression and parent full-scope tests after a forward fix. A new source commit requires fresh independent reviews and verification.
