#!/bin/sh
set -eu

# BuildKit refuses to start in rootless mode unless it is running as the mapped
# root inside a user namespace. RootlessKit creates that namespace and provides
# the user-space network path used by the daemon.
#
# Do not copy up /run: buildkitd listens on
# $XDG_RUNTIME_DIR/buildkit/buildkitd.sock, and that socket must remain visible
# to clients in the container namespace.
exec rootlesskit \
    --net=slirp4netns \
    --disable-host-loopback \
    --copy-up=/etc \
    --state-dir=/home/ragnarsec/.local/share/buildkit/rootlesskit \
    buildkitd --root /home/ragnarsec/.local/share/buildkit "$@"
