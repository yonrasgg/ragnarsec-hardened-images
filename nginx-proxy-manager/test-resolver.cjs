const assert = require("node:assert/strict");
const { test } = require("node:test");
const { renderResolver } = require("./render-resolver.cjs");

test("uses Docker DNS and preserves the order of unique IPv4 nameservers", () => {
    const input = "  nameserver\t127.0.0.11 # Docker\nnameserver 198.51.100.53\nnameserver 127.0.0.11\n";
    assert.equal(renderResolver(input), "resolver 127.0.0.11 198.51.100.53 ipv6=off;\n");
});

test("does not turn IPv6, invalid IPs or other resolv.conf directives into Nginx options", () => {
    const input = "# nameserver 1.1.1.1\r\nnameserver fe80::1%eth0\nnameserver 127.0.0.11;\n" +
        "nameserver 300.0.0.1\nsearch 192.0.2.53\nnameserver 192.0.2.53\r\n";
    assert.equal(renderResolver(input), "resolver 192.0.2.53 ipv6=off;\n");
});

test("writes an empty include when IPv4 DNS is absent without falling back to public DNS", () => {
    assert.equal(renderResolver("options ndots:0\nnameserver ::1\nnameserver garbage\n"), "");
    assert.equal(renderResolver(""), "");
});
