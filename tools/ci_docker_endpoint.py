#!/usr/bin/env python3
"""Fail closed on an implicit or cross-user CI Docker endpoint.

Metadata only: no client config contents, credential helpers or daemon mutation.
Not a sandbox: trusted pipeline code can change its own process environment.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import struct


def validate_environment(env, uid):
    if uid == 0 or env.get("XDG_RUNTIME_DIR") != f"/run/user/{uid}":
        raise ValueError("ci-runtime-uid-mismatch")
    endpoint = f"/run/user/{uid}/docker.sock"
    if env.get("DOCKER_HOST") != "unix://" + endpoint:
        raise ValueError("ci-docker-endpoint-mismatch")
    for key in ("DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY",
                "DOCKER_CERT_PATH", "DOCKER_API_VERSION", "BUILDX_CONFIG"):
        if env.get(key):
            raise ValueError("ci-docker-override:" + key)
    if env.get("BUILDX_BUILDER", "") not in ("", "default"):
        raise ValueError("ci-builder-override")
    temporary = Path(env.get("WORKSPACE_TMP", ""))
    expected = temporary / "ragnarsec-ci" / "docker-auth"
    if (not temporary.is_absolute() or ".." in temporary.parts or
            env.get("DOCKER_CONFIG") != str(expected)):
        raise ValueError("ci-docker-config-not-build-local")
    return endpoint


def no_symlinks(path):
    for part in reversed([path, *path.parents]):
        try:
            item = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(item.st_mode):
            raise ValueError("ci-symlink-path")


def validate_filesystem(env, uid, require_fresh=True):
    runtime = Path(env["XDG_RUNTIME_DIR"])
    no_symlinks(runtime)
    item = runtime.lstat()
    if (not stat.S_ISDIR(item.st_mode) or item.st_uid != uid or
            stat.S_IMODE(item.st_mode) & 0o077):
        raise ValueError("ci-runtime-permissions")
    config = Path(env["DOCKER_CONFIG"])
    no_symlinks(config)
    if config.exists():
        if require_fresh:
            raise ValueError("ci-docker-config-must-be-fresh")
        item = config.lstat()
        if (not stat.S_ISDIR(item.st_mode) or item.st_uid != uid or
                stat.S_IMODE(item.st_mode) & 0o077):
            raise ValueError("ci-docker-config-permissions")
    endpoint = runtime / "docker.sock"
    item = endpoint.lstat()
    if not stat.S_ISSOCK(item.st_mode) or item.st_uid != uid:
        raise ValueError("ci-docker-socket-owner")


def summarize_info(info):
    if "name=rootless" not in info.get("SecurityOptions", []):
        raise ValueError("ci-daemon-not-rootless")
    return {"rootless": True, "server_version": info.get("ServerVersion")}


class OwnSocketHTTP(http.client.HTTPConnection):
    def __init__(self, endpoint, uid):
        super().__init__("localhost", timeout=5)
        self.endpoint, self.uid = endpoint, uid

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        try:
            self.sock.connect(self.endpoint)
            _, self.peer_uid, _ = struct.unpack(
                "3i", self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if self.peer_uid != self.uid:
                raise ValueError("ci-daemon-peer-uid")
        except BaseException:
            self.sock.close()
            raise


def probe(endpoint, uid):
    connection = OwnSocketHTTP(endpoint, uid)
    try:
        connection.request("GET", "/info", headers={"Connection": "close"})
        if connection.peer_uid != uid:
            raise ValueError("ci-daemon-peer-uid")
        response = connection.getresponse()
        data = response.read(262145)
        if response.status != 200 or len(data) > 262144:
            raise ValueError("ci-daemon-info-response")
        return summarize_info(json.loads(data))
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-only", action="store_true",
                        help="Post-step config safety check, no daemon request")
    args = parser.parse_args()
    uid = os.geteuid()
    endpoint = validate_environment(os.environ, uid)
    validate_filesystem(os.environ, uid, require_fresh=not args.config_only)
    if args.config_only:
        print("CI Docker config metadata checks passed")
    else:
        observed = probe(endpoint, uid)
        print(json.dumps({"endpoint": "unix://" + endpoint, "uid": uid, **observed}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, http.client.HTTPException):
        raise SystemExit("STOP: CI Docker endpoint check failed; no fallback or raw config output")
