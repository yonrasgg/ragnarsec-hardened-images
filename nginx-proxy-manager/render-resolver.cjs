const fs = require("node:fs");
const { isIPv4 } = require("node:net");

function renderResolver(contents) {
    const nameservers = new Set();
    for (const line of contents.split("\n")) {
        const [directive, address] = line.trim().split(/\s+/);
        if (directive === "nameserver" && isIPv4(address ?? "")) nameservers.add(address);
    }
    return nameservers.size ? `resolver ${[...nameservers].join(" ")} ipv6=off;\n` : "";
}

if (require.main === module) {
    fs.writeFileSync("/tmp/npm/resolvers.conf", renderResolver(fs.readFileSync("/etc/resolv.conf", "utf8")),
        { mode: 0o600 });
}

module.exports = { renderResolver };
