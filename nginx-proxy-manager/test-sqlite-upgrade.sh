#!/usr/bin/env bash
# Local compatibility proof with an exact 2.16.0 fixture image already present.
set -euo pipefail
old=${1:?exact NPM 2.16.0 image ID required}
new=${2:?exact NPM 2.17.1 candidate image ID required}
[[ $old =~ ^sha256:[a-f0-9]{64}$ && $new =~ ^sha256:[a-f0-9]{64}$ ]]
receipt=$(mktemp -d /tmp/opencode/npm117-sqlite-upgrade.XXXXXXXX)
printf 'Evidence directory: %s\n' "$receipt"
printf '%s\n' "$old" "$new" >"$receipt/image-ids.txt"
common=(--rm --pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges
    --user 1000:1000 -e NODE_ENV=production
    --tmpfs /data:rw,noexec,nosuid,nodev,size=32m,mode=0750,uid=1000,gid=1000
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=24m,mode=1777)

docker run -i "${common[@]}" --entrypoint sh "$old" -ec '
    node --input-type=module 1>&2
    cat /data/database.sqlite
' >"$receipt/preimage.sqlite" 2>"$receipt/seed.log" <<'JS'
import { migrateUp } from "./migrate.js";
import Database from "better-sqlite3";
import {createRequire} from "node:module";
if (createRequire(import.meta.url)("./package.json").version !== "2.16.0") process.exit(2);
await migrateUp();
const db = new Database("/data/database.sqlite");
db.prepare("insert into setting (id,name,description,value,meta) values (?,?,?,?,?)").run(
    "synthetic-upgrade", "Synthetic upgrade", "Disposable fixture", "expected", "{}");
db.pragma("wal_checkpoint(TRUNCATE)");
db.close();
process.exit(0);
JS
chmod 0444 "$receipt/preimage.sqlite"
( cd "$receipt" && sha256sum preimage.sqlite > PREIMAGE-SHA256SUMS.txt )
mount=(--mount "type=bind,source=$receipt/preimage.sqlite,destination=/seed.sqlite,readonly")

docker run -i "${common[@]}" "${mount[@]}" \
    --tmpfs /etc/letsencrypt:rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=1000,gid=1000 \
    --entrypoint sh "$new" -se <<'SH' | tee "$receipt/upgrade.log"
umask 077
cp /seed.sqlite /data/database.sqlite
chmod 0600 /data/database.sqlite
/usr/local/bin/npm-start >/tmp/npm-upgrade.log 2>&1 &
npm=$!
trap 'kill -TERM "$npm" 2>/dev/null || :; wait "$npm" || :' EXIT
ready=false
for _ in $(seq 1 30); do
    if wget -qO /tmp/health.json http://127.0.0.1:8181/api/ 2>/dev/null; then ready=true; break; fi
    if ! kill -0 "$npm" 2>/dev/null; then break; fi
    sleep 1
done
if ! "$ready"; then tail -20 /tmp/npm-upgrade.log; exit 1; fi
node <<'JS'
const assert = require("node:assert/strict");
const Database = require("better-sqlite3");
const open = (path) => new Database(path, {readonly:true});
const before = open("/seed.sqlite");
const after = open("/data/database.sqlite");
// migrateUp reads currentVersion() from Knex's default table but runs against "migrations".
const history = (db) => db.prepare("select name from migrations order by id").all().map(x=>x.name);
assert(after.pragma("integrity_check", {simple:true}) === "ok");
assert.equal(require("/tmp/health.json").status, "OK");
assert.equal(after.prepare("select value from setting where id=?").pluck().get("synthetic-upgrade"), "expected");
assert.deepEqual(history(after).slice(0, history(before).length), history(before));
assert(history(after).slice(history(before).length).includes("20260906220000_user_permission_meta.js"));
console.log(JSON.stringify({case:"synthetic-upgrade",old_migrations:history(before).length,new_migrations:history(after).length,setting_preserved:true,integrity:"ok"}));
before.close();
after.close();
JS
SH

# Rollback uses a fresh copy of the untouched preimage with the old engine.
docker run -i "${common[@]}" "${mount[@]}" --entrypoint node "$old" <<'JS' | tee "$receipt/restore.log"
const assert=require("node:assert/strict");
const fs=require("node:fs");
const Database=require("better-sqlite3");
fs.copyFileSync("/seed.sqlite", "/data/database.sqlite");
const db=new Database("/data/database.sqlite", {readonly:true});
assert.equal(db.pragma("integrity_check", {simple:true}),"ok");
assert.equal(db.prepare("select value from setting where id=?").pluck().get("synthetic-upgrade"),"expected");
assert.equal(db.prepare("select count(*) from migrations where name like '%user_permission_meta%'").pluck().get(),0);
console.log("NPM_2160_SQLITE_PREIMAGE_RESTORE_OK");
db.close();
JS
( cd "$receipt" && sha256sum -c PREIMAGE-SHA256SUMS.txt && sha256sum ./*.log image-ids.txt > SHA256SUMS.txt )
