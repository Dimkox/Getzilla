#!/bin/sh
# Use the checkout containing this launcher, including from another project.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec "$here/../bin/getzilla" self-uninstall "$@"
