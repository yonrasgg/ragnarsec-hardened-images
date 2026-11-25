"""Opt-in, fail-closed admin UI projection; never initializes WGDashboard databases."""
import base64
import binascii
import configparser
import ipaddress
import os
import re
import stat
from pathlib import Path


READ_ONLY = os.environ.get("WG_DASHBOARD_READ_ONLY") == "1"

# Exact method/path pairs. No path prefixes, implicit HEAD, API key, OIDC, client
# API, raw configuration, backups, downloads, diagnostics or plugins.
ADMIN_GET = frozenset({
    "/api/handshake",
    "/api/validateAuthentication",
    "/api/requireAuthentication",
    "/api/getWireguardConfigurations",
    "/api/getWireguardConfigurationInfo",
    "/api/getDashboardConfiguration",
    "/api/getDashboardTheme",
    "/api/getDashboardVersion",
    "/api/getDashboardUpdate",
    "/api/systemStatus",
    "/api/oidc/providers",
    "/api/isTotpEnabled",
    "/api/locale",
    "/api/locale/available",
    "/api/signout",
})
ADMIN_POST = frozenset({"/api/authenticate"})
PUBLIC_CONFIG = {
    "Account": ("username",),
    "Server": ("dashboard_theme", "dashboard_language", "dashboard_sort",
               "dashboard_peer_list_display", "dashboard_refresh_interval", "version"),
}
PEER_FIELDS = frozenset({"PublicKey", "AllowedIPs"})
INTERFACE_FIELDS = frozenset({"Address", "ListenPort", "MTU"})
SECTION = re.compile(r"\[(Interface|Peer)\]")
ASSIGNMENT = re.compile(r"([A-Za-z][A-Za-z0-9]*)[ \t]*=[ \t]*(.*)")
SAFE_FILENAME = re.compile(r"[A-Za-z0-9_-]{1,64}\.conf")
MAX_CONF_BYTES = 1024 * 1024
MAX_FILES = 64
# Bcrypt modular crypt format: $2a/$2b/$2y, bounded cost 04..16, 22-char
# salt and 31-char digest in bcrypt's radix-64 alphabet. This is syntax only.
BCRYPT_ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
BCRYPT_FORMAT = re.compile(
    r"\$2[aby]\$(?:0[4-9]|1[0-6])\$([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})"
)


def valid_bcrypt_hash(value):
    if not isinstance(value, str) or len(value) != 60:
        return False
    match = BCRYPT_FORMAT.fullmatch(value)
    return (match is not None
            and BCRYPT_ALPHABET.index(match.group(1)[-1]) % 16 == 0
            and BCRYPT_ALPHABET.index(match.group(2)[-1]) % 4 == 0)


def invalid_inventory():
    # Never echo paths, directive names or values from untrusted fixture bytes.
    raise RuntimeError("invalid keyless inventory") from None


def keyless_directory(config_path, configured):
    """Require a preexisting, local, ordinary fixture tree under the ini parent."""
    base = config_path.absolute()
    if not base.is_dir() or base.is_symlink() or base.is_mount() or base.resolve().is_relative_to("/etc"):
        raise RuntimeError("read-only UI requires a regular local configuration directory")
    directory = Path(configured)
    if not directory.is_absolute() or ".." in directory.parts:
        raise RuntimeError("read-only UI requires an absolute keyless directory without traversal")
    try:
        relative = directory.relative_to(base)
    except ValueError:
        raise RuntimeError("keyless directory must be below CONFIGURATION_PATH") from None
    if directory.is_symlink():
        raise RuntimeError("symlink in keyless directory path")
    if not relative.parts or not directory.is_dir() or directory.is_mount():
        raise RuntimeError("keyless directory must be a preexisting regular subdirectory")
    cursor = base
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise RuntimeError("symlink in keyless directory path")
    if not directory.resolve().is_relative_to(base.resolve()):
        raise RuntimeError("keyless directory escapes CONFIGURATION_PATH")
    try:
        children = list(directory.iterdir())
        if len(children) > MAX_FILES:
            invalid_inventory()
        for child in children:
            if child.is_symlink() or not child.is_file() or not SAFE_FILENAME.fullmatch(child.name):
                invalid_inventory()
            parse_configuration(child)
    except OSError:
        invalid_inventory()
    return directory


def permitted(method, path, prefix=""):
    if method == "GET" and path == f"{prefix}/":
        return True
    if method == "GET" and (path.startswith(f"{prefix}/assets/") or
                            path.startswith(f"{prefix}/img/") or
                            path.startswith(f"{prefix}/json/")):
        return True  # only Flask's static handler resolves files
    if method == "GET" and path in {prefix + p for p in ADMIN_GET}:
        return True
    return method == "POST" and path in {prefix + p for p in ADMIN_POST}


class ReadOnlyConfig:
    """Read an existing ini; never create, migrate or open databases."""
    DashboardVersion = "v4.3.4"
    APIAccessed = False

    def __init__(self):
        config_path = Path(os.environ.get("CONFIGURATION_PATH", "."))
        if (not config_path.is_dir() or config_path.is_symlink() or config_path.is_mount() or
                config_path.resolve().is_relative_to("/etc")):
            raise RuntimeError("read-only UI requires a local regular configuration directory")
        path = config_path / "wg-dashboard.ini"
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("read-only UI requires a regular existing ini file")
        self._config = configparser.RawConfigParser(strict=False)
        try:
            with path.open("r", encoding="utf-8") as stream:
                self._config.read_file(stream)
        except (OSError, UnicodeError, configparser.Error):
            raise RuntimeError("invalid read-only ini") from None
        # Do not turn a partially configured installation into anonymous access.
        try:
            auth_required = self._config.getboolean("Server", "auth_req")
            username = self._config.get("Account", "username")
            password = self._config.get("Account", "password")
        except (ValueError, configparser.Error):
            raise RuntimeError("invalid read-only ini") from None
        if not auth_required:
            raise RuntimeError("read-only UI requires Server.auth_req=true")
        if not username or not valid_bcrypt_hash(password):
            raise RuntimeError("read-only UI requires an existing bcrypt account")
        configured = self._config.get("Server", "wg_conf_path", fallback="").strip()
        if not configured:
            raise RuntimeError("read-only UI requires Server.wg_conf_path")
        self.wg_conf_path = keyless_directory(config_path, configured)
        self.DashboardAPIKeys = []

    def GetConfig(self, section, key):
        if not self._config.has_option(section, key):
            return False, None
        value = self._config.get(section, key)
        if value.lower() in ("1", "yes", "true", "on"):
            value = True
        elif value.lower() in ("0", "no", "false", "off"):
            value = False
        return True, value

    def toJson(self):
        result = {
            section: {
                key: self.GetConfig(section, key)[1]
                for key in keys if self._config.has_option(section, key)
            }
            for section, keys in PUBLIC_CONFIG.items()
        }
        result["Server"].setdefault("dashboard_refresh_interval", "60000")
        result["Server"].setdefault("dashboard_peer_list_display", "grid")
        result["Server"].setdefault("dashboard_sort", "status")
        result["Server"].setdefault("dashboard_theme", "dark")
        result["Server"]["dashboard_api_key"] = False
        result["Server"]["read_only"] = True
        result["Clients"] = {"enable": False, "sign_up": False}
        result["OIDC"] = {"admin_enable": False, "client_enable": False}
        result["WireGuardConfiguration"] = {"peer_tracking": False, "autostart": []}
        return result


def _public_value(key, value):
    if not value or any(ord(char) < 32 for char in value):
        invalid_inventory()
    if key in ("Address", "AllowedIPs"):
        parts = [part.strip() for part in value.split(",")]
        if not all(parts):
            invalid_inventory()
        try:
            for part in parts:
                if key == "Address":
                    ipaddress.ip_interface(part)
                else:
                    ipaddress.ip_network(part, strict=False)
        except ValueError:
            invalid_inventory()
        return ", ".join(parts)
    if key in ("ListenPort", "MTU"):
        low = 1 if key == "ListenPort" else 576
        if len(value) > 5 or not re.fullmatch(r"[0-9]+", value) or not low <= int(value) <= 65535:
            invalid_inventory()
        return str(int(value))
    if key == "PublicKey":
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            invalid_inventory()
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
            invalid_inventory()
        return value
    invalid_inventory()


def parse_configuration(path):
    """Strictly parse a bounded synthetic keyless WG projection, no fallbacks."""
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_size > MAX_CONF_BYTES:
            invalid_inventory()
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            source = stream.read(MAX_CONF_BYTES + 1)
        if not source or len(source) > MAX_CONF_BYTES or b"\x00" in source:
            invalid_inventory()
        text = source.decode("utf-8")
    except (OSError, UnicodeError):
        invalid_inventory()
    finally:
        if fd >= 0:
            os.close(fd)
    if text.startswith("\ufeff") or "\r" in text:
        invalid_inventory()
    sections = []
    for raw_line in text.splitlines():
        if any(ord(char) < 32 and char != "\t" for char in raw_line):
            invalid_inventory()
        line = raw_line.strip()
        if not line:
            continue
        # The upstream fixture exporter strips all comments; reject extras
        # rather than retaining possible credentials in comment text.
        if line.startswith(("#", ";")):
            invalid_inventory()
        section_match = SECTION.fullmatch(line)
        if section_match:
            name = section_match.group(1)
            if name == "Interface" and sections:
                invalid_inventory()
            if name == "Peer" and (not sections or sections[0][0] != "Interface"):
                invalid_inventory()
            sections.append((name, {}))
            continue
        assignment = ASSIGNMENT.fullmatch(line)
        if not assignment or not sections:
            invalid_inventory()
        key, value = assignment.groups()
        section_name, fields = sections[-1]
        allowed = INTERFACE_FIELDS if section_name == "Interface" else PEER_FIELDS
        if key not in allowed or key in fields:
            invalid_inventory()
        fields[key] = _public_value(key, value.strip())
    if not sections or "Address" not in sections[0][1]:
        invalid_inventory()
    interface = sections[0][1]
    peers = [fields for name, fields in sections[1:]]
    if any("PublicKey" not in peer or "AllowedIPs" not in peer for peer in peers):
        invalid_inventory()
    if len({peer["PublicKey"] for peer in peers}) != len(peers):
        invalid_inventory()
    public_peers = []
    for peer in peers:
        public_peers.append({
            "id": peer["PublicKey"], "allowed_ip": peer["AllowedIPs"],
            "name": "", "status": "unknown", "latest_handshake": "Unknown",
            "endpoint": "", "cumu_receive": 0.0, "total_receive": 0.0,
            "cumu_sent": 0.0, "total_sent": 0.0, "cumu_data": 0.0,
            "total_data": 0.0, "jobs": [], "ShareLink": [],
        })
    return interface, public_peers


def snapshots(config):
    """Read only regular files; do not initialize a database or run wg."""
    directory = keyless_directory(
        Path(os.environ.get("CONFIGURATION_PATH", ".")), config.wg_conf_path
    )
    result = []
    for path in sorted(directory.glob("*.conf")):
        interface, peers = parse_configuration(path)
        result.append(({
                "Name": path.stem, "Protocol": "wg", "Status": None, "StatusKnown": False,
                "PublicKey": "", "Address": interface.get("Address", ""),
                "ListenPort": interface.get("ListenPort", ""),
                "DataUsage": {"Total": 0, "Sent": 0, "Receive": 0},
                "ConnectedPeers": None, "TotalPeers": len(peers),
                "Info": {"PeerGroups": {}}, "Table": "", "SaveConfig": False,
        }, peers))
    return result


def configurations(config):
    return [configuration for configuration, _ in snapshots(config)]


def configuration_info(config, name):
    """Only names discovered in the configured directory; no user path joins."""
    for configuration, peers in snapshots(config):
        if configuration["Name"] == name:
            return {
                "configurationInfo": configuration,
                "configurationPeers": peers,
                "configurationRestrictedPeers": [],
            }
    return None
