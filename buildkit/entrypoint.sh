#!/bin/sh
set -eu

# BuildKit refuses to start in rootless mode unless it is running as the mapped
# root inside a user namespace. RootlessKit creates that namespace and provides
# the user-space network path used by the daemon.
exec rootlesskit \
    --net=slirp4netns \
    --disable-host-loopback \
    --copy-up=/etc \
    --copy-up=/run \
    --state-dir=/home/ragnarsec/.local/share/buildkit/rootlesskit \
    buildkitd --root /home/ragnarsec/.local/share/buildkit "$@"
