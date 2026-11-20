const fs = require("node:fs");
const path = require("node:path");

const [source, target] = process.argv.slice(2);
const upstream = (p) => path.join(source, p);
const output = (p) => path.join(target, p);
function copy(from, to) {
    const next = output(to);
    fs.mkdirSync(path.dirname(next), { recursive: true });
    fs.cpSync(upstream(from), next, { recursive: true, verbatimSymlinks: true });
}
function edit(file, transform) {
    const next = output(file);
    const text = fs.readFileSync(next, "utf8");
    const result = transform(text);
    if (result === text) throw new Error(`Expected upstream patch: ${file}`);
    fs.writeFileSync(next, result);
}
function replace(text, expression, replacement) {
    if (!expression.test(text)) throw new Error(`Upstream input changed: ${expression}`);
    return text.replace(expression, replacement);
}

copy("backend", "app");
copy("frontend/dist", "app/frontend");
for (const file of ["etc/nginx", "etc/letsencrypt.ini",
    "etc/logrotate.d/nginx-proxy-manager", "var/www/html"]) copy(`rootfs/${file}`, file);
fs.unlinkSync(output("etc/nginx/conf.d/dev.conf"));
// The ACME directory is selected at runtime (LE_SERVER). A fixed `preferred-chain`
// names a public Let's Encrypt root and breaks issuance against a private CA.
edit("etc/letsencrypt.ini", (s) => replace(s, /^preferred-chain = .*\n/m, ""));

edit("app/schema/paths/nginx/certificates/certID/upload/post.json", (text) => {
    const schema = JSON.parse(text);
    const media = schema.responses["200"].content["application/json"];
    const example = media.examples.default.value.certificate_key;
    if (media.schema.properties.certificate_key.type !== "string" || !example.includes("PRIVATE KEY-----")) {
        throw new Error("Upstream certificate example changed");
    }
    delete media.examples.default.value.certificate_key;
    return `${JSON.stringify(schema, null, 2)}\n`;
});
edit("app/index.js", (s) => replace(s, /app\.listen\(3000, \(\)/, 'app.listen(3000, "127.0.0.1", ()'));
edit("app/internal/nginx.js", (s) => replace(s, /error_log off;/, "error_log stderr;"));
edit("app/setup.js", (s) => replace(s, /logrotate \/etc\/logrotate/, "logrotate -s /data/logs/logrotate.status /etc/logrotate"));
edit("etc/logrotate.d/nginx-proxy-manager", (s) => replace(s, /\/run\/nginx\/nginx\.pid/g, "/tmp/npm/nginx.pid")
    .replace(/^    su npm npm\n/gm, ""));
edit("etc/nginx/nginx.conf", (s) => {
    let text = replace(s, /^pid .*;/m, "pid /tmp/npm/nginx.pid;");
    text = replace(text, /^user npm;\n/m, "");
    text = replace(text, /worker_processes auto;/, "worker_processes 1;");
    text = replace(text, /\/tmp\/nginx\/body/, "/tmp/npm/body");
    text = replace(text, /\/var\/lib\/nginx\/cache\//g, "/tmp/npm/cache/");
    text = replace(text, /(^\s*client_body_temp_path .*;)/m,
        "$1\n\tproxy_temp_path /tmp/npm/proxy;\n\tfastcgi_temp_path /tmp/npm/fastcgi;\n\tuwsgi_temp_path /tmp/npm/uwsgi;\n\tscgi_temp_path /tmp/npm/scgi;");
    text = replace(text, /(^\s*include \/etc\/nginx\/conf\.d\/\*\.conf;)/m, "$1\n\tinclude /tmp/npm/production.conf;");
    return replace(text, /^\s*include \/etc\/nginx\/conf\.d\/include\/resolvers\[\.\]conf;\n/m, "\n");
});
edit("etc/nginx/conf.d/production.conf.template", (s) => replace(s, /listen \{\{NPM_ADMIN_PORT\}\}/, "listen 127.0.0.1:{{NPM_ADMIN_PORT}}")
    .replace(/^[ \t]*listen \[::\]:\{\{NPM_ADMIN_PORT\}\}.*\n/m, ""));
edit("etc/nginx/conf.d/default.conf", (s) => replace(s, /^[ \t]*listen \[::\]:.*\n/gm, ""));
fs.mkdirSync(output("etc/nginx/modules"), { recursive: true });
fs.writeFileSync(output("etc/nginx/modules/geoip2.conf"), "load_module /usr/lib/nginx/modules/ngx_http_geoip2_module.so;\n");
