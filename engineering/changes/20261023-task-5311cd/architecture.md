# Architecture

Linux process management must use controller pidfd APIs to preserve process identity. Host preflight must check these APIs before creating a child. Return the existing unsupported-host result when an API is unavailable. Do not add PID-only signal fallbacks.

Use UV_PYTHON=/usr/bin/python3.12, UV_NO_MANAGED_PYTHON=1, UV_PYTHON_DOWNLOADS=never and UV_LOCKED=1 for fresh Factory validation. This selects an installed supported interpreter. It does not weaken product checks or change locks.

No producer, consumer, public payload, migration or external write changes. Rollback is a source revert.
