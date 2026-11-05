## 2026-11-04 — Restart completed workers before handing off repairs

Repair findings were sent to a completed worker with `send_message`. The messages queued but did not start a new turn. The coordinator waited for work that had no active owner, which delayed the Core repair batch by about 16 minutes.

Check the worker status before handing off new work. Use `followup_task` to restart a completed worker. Use `send_message` to coordinate with an active worker, then confirm that the task is running.

The affected delivery was [Core PR #333](https://github.com/Dimkox/Getzilla/pull/333).
