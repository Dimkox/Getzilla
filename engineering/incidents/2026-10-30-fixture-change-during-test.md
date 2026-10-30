## 2026-10-30 — Keep fixture bytes fixed during a run

The writer changed the pinned fixture while a Docker test suite was still using it. Later cases failed image verification against the old digest, so that run did not verify either complete tree. Finish the test before changing its inputs, then rerun against the fixed tree. The associated pull request was not yet known.
