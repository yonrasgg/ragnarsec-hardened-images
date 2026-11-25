"""Offline keyless byte preflight. Standard library only; no app imports/writes."""
import base64
import binascii
import configparser
import ipaddress
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 1024 * 1024
MAX_FILES = 64
FILE_NAME = re.compile(r"[A-Za-z0-9_-]{1,59}\.conf")
BCRYPT_FORMAT = re.compile(r"\$2[aby]\$(?:0[4-9]|1[0-6])\$([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})")
BCRYPT_ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
FIELDS = {
    "Interface": ("Address", "ListenPort", "MTU"),
    "Peer": ("PublicKey", "AllowedIPs"),
}
SECTION = re.compile(r"\[(Interface|Peer)\]")
ASSIGNMENT = re.compile(r"([A-Za-z][A-Za-z0-9]*)[ \t]*=[ \t]*(.*)")


class Invalid(ValueError):
    pass


def canonical_value(key, value):
    if key in ("Address", "AllowedIPs"):
        parts = [part.strip() for part in value.split(",")]
        if not all(parts):
            raise Invalid("empty address")
        try:
            for part in parts:
                if key == "Address":
                    ipaddress.ip_interface(part)
                else:
                    ipaddress.ip_network(part, strict=False)
        except ValueError as exc:
            raise Invalid("invalid address") from exc
        return ", ".join(parts)
    if key in ("ListenPort", "MTU"):
        low = 1 if key == "ListenPort" else 576
        if len(value) > 5 or not re.fullmatch(r"[0-9]+", value) or not low <= int(value) <= 65535:
            raise Invalid("invalid number")
        return str(int(value))
    if key == "PublicKey":
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise Invalid("invalid public key") from exc
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
            raise Invalid("invalid public key")
        return value
    raise Invalid("unknown value")


def canonical_projection(source):
    """Equivalent to projector project_bytes only for inputs already canonical.

    Unlike project_bytes, secret directives and comments are never discarded:
    this preflight rejects any input whose canonical projection differs.
    """
    if len(source) > MAX_BYTES or not source or b"\x00" in source:
        raise Invalid("invalid input bytes")
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Invalid("invalid UTF-8") from exc
    if text.startswith("\ufeff") or "\r" in text:
        raise Invalid("BOM/CR")
    sections = []
    for raw_line in text.splitlines():
        if any(ord(char) < 32 and char != "\t" for char in raw_line):
            raise Invalid("control character")
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(("#", ";")):
            raise Invalid("noncanonical comment")
        section = SECTION.fullmatch(line)
        if section:
            name = section.group(1)
            if name == "Interface" and sections:
                raise Invalid("duplicate interface")
            if name == "Peer" and (not sections or sections[0][0] != "Interface"):
                raise Invalid("peer before interface")
            sections.append((name, {}))
            continue
        assignment = ASSIGNMENT.fullmatch(line)
        if not assignment or not sections:
            raise Invalid("invalid assignment")
        key, value = assignment.groups()
        name, fields = sections[-1]
        if key not in FIELDS[name] or key in fields:
            raise Invalid("unknown or repeated field")
        fields[key] = canonical_value(key, value.strip())
    if not sections or sections[0][0] != "Interface" or "Address" not in sections[0][1]:
        raise Invalid("missing interface/address")
    peers = [fields for _, fields in sections[1:]]
    if any("PublicKey" not in peer or "AllowedIPs" not in peer for peer in peers):
        raise Invalid("incomplete peer")
    if len({peer["PublicKey"] for peer in peers}) != len(peers):
        raise Invalid("duplicate peer")
    lines = []
    for name, fields in sections:
        lines.append(f"[{name}]")
        lines.extend(f"{key} = {fields[key]}" for key in FIELDS[name] if key in fields)
        lines.append("")
    result = ("\n".join(lines).rstrip() + "\n").encode("utf-8")
    if result != source:
        raise Invalid("not exact canonical projected bytes")
    return result


def plain_path(value):
    if not value or not value.startswith("/") or value == "/":
        raise Invalid("non-absolute path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts[1:]):
        raise Invalid("noncanonical path")
    cursor = Path("/")
    for part in parts[1:]:
        cursor /= part
        if stat.S_ISLNK(os.lstat(cursor).st_mode):
            raise Invalid("linked path component")
    return Path(value)


def read_regular(path, limit, *, directory_fd=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > limit:
            raise Invalid("nonregular or oversized file")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise Invalid("oversized file")
        return data
    finally:
        if fd >= 0:
            os.close(fd)


def bcrypt_format_only(value):
    """Check bcrypt's encoded shape/padding, never verify a password."""
    match = BCRYPT_FORMAT.fullmatch(value)
    if not match:
        return False
    salt, digest = match.groups()
    return (
        BCRYPT_ALPHABET.index(salt[-1]) % 16 == 0
        and BCRYPT_ALPHABET.index(digest[-1]) % 4 == 0
    )


def validate():
    data = plain_path(os.environ["WG_DASHBOARD_READ_ONLY_DATA_DIR"])
    wg = plain_path(os.environ["WG_DASHBOARD_READ_ONLY_WG_DIR"])
    if data == Path("/etc") or Path("/etc") in data.parents:
        raise Invalid("host /etc forbidden")
    if wg.parent != data or not data.is_dir() or not wg.is_dir():
        raise Invalid("keyless tree must be direct data child")
    if data.is_mount() or wg.is_mount():
        raise Invalid("mountpoint not proven safe")
    ini = read_regular(str(data / "wg-dashboard.ini"), MAX_BYTES)
    if b"\x00" in ini:
        raise Invalid("NUL in INI")
    parser = configparser.RawConfigParser(strict=True)
    parser.read_string(ini.decode("utf-8"))
    if parser.get("Server", "auth_req") != "true":
        raise Invalid("authentication not required")
    if parser.get("Server", "wg_conf_path") != str(wg):
        raise Invalid("different keyless path")
    if not parser.get("Account", "username") or not bcrypt_format_only(
        parser.get("Account", "password")
    ):
        raise Invalid("missing complete bcrypt-shaped account")
    fd = os.open(wg, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        count = 0
        with os.scandir(fd) as entries:
            for entry in entries:
                count += 1
                if count > MAX_FILES:
                    raise Invalid("file count")
                name = entry.name
                if not FILE_NAME.fullmatch(name):
                    raise Invalid("invalid filename")
                canonical_projection(read_regular(name, MAX_BYTES, directory_fd=fd))
        if count < 1:
            raise Invalid("file count")
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        validate()
    except (Invalid, OSError, UnicodeError, KeyError, configparser.Error) as exc:
        # No path, field or secret content in the refusal output.
        print(f"read-only preflight rejected: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(64) from None
