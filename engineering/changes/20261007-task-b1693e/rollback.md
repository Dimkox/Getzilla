# Rollback

## Source recovery
Revert the isolated landing commit through the repository's normal PR process if a regression is found. Do not reset shared branches or alter existing unrelated commits.

## Production recovery
Before an authorized upload, retain the currently served index.html and the exact existing host configuration outside the public directory. Publish new assets first and HTML last. If live verification fails, restore the previous index.html; leave new hashed files temporarily in place because they are inert without references. Restore only configuration entries changed by this release if such a separate operation was authorized. Recheck old HTML identity, its original remote image/font resources, both unchanged analytics scripts and the first-body tracking pixel.

No database, runtime, secret, or factory rollback is involved.
