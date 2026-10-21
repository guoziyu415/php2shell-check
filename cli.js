#!/usr/bin/env node
/* php2shell-check CLI. Reads files or stdin and says which PHP installs need the
   October 2026 fix for CVE-2026-109618 and CVE-2026-109619. It never connects anywhere.
   Usage:
     php2shell-check Dockerfile docker-compose.yml
     php -v | php2shell-check
     dpkg -l | grep php | php2shell-check
     php2shell-check --json Dockerfile
     php2shell-check --lang en Dockerfile
   Exit code 1 when anything needs action, 0 when everything is fixed or only informational.
   MIT License. https://github.com/guoziyu415/php2shell-check */
"use strict";
var fs = require("fs"), path = require("path");
var P = require(path.join(__dirname, "php2shell-check.js"));
var args = process.argv.slice(2), files = [], json = false, lang = "ja";
for (var i = 0; i < args.length; i++) {
  if (args[i] === "--json") json = true;
  else if (args[i] === "--lang") lang = args[++i];
  else if (args[i] === "-h" || args[i] === "--help") { console.log(fs.readFileSync(__filename, "utf8").split("*/")[0].replace(/^[\s\S]*?Usage:\n/, "Usage:\n").replace(/^ {3}/gm, "")); process.exit(0); }
  else files.push(args[i]);
}
var tty = process.stdout.isTTY && !process.env.NO_COLOR;
var COL = { fixed: 84, pull: 51, vendor: 220, unknownpatch: 220, vulnerable: 208, eolbackport: 204, eolnone: 204, info: 244 };
function c(code, s) { return tty ? "\x1b[38;5;" + code + "m" + s + "\x1b[0m" : s; }
function run(name, text) {
  var r = P.analyze(text);
  if (json) { console.log(JSON.stringify({ file: name, worst: r.worst, rows: r.rows.map(function (x) { var e = P.explain(x, lang); return { line: x.find.line, status: x.st, what: e.head, mode: e.sapi, fix: x.fix, note: e.text }; }) })); return r.worst; }
  console.log((tty ? "\x1b[1m" : "") + name + (tty ? "\x1b[0m" : "") + (r.rows.length ? "" : "  " + (lang === "en" ? "no PHP version found" : "PHP の版が見つかりませんでした")));
  r.rows.forEach(function (x) {
    var e = P.explain(x, lang);
    console.log("  " + String(x.find.line).padStart(4) + "  " + c(COL[x.st], P.ST[x.st][lang]) + "  " + e.head + "  [" + e.sapi + "]");
    if (x.fix) console.log("        → " + c(84, x.fix));
    console.log("        " + e.text);
  });
  return r.worst;
}
var worst = -1;
if (!files.length) {
  if (process.stdin.isTTY) { console.error("Give a file, or pipe text in. php2shell-check --help"); process.exit(2); }
  var buf = ""; process.stdin.setEncoding("utf8");
  process.stdin.on("data", function (d) { buf += d; });
  process.stdin.on("end", function () { process.exit(run("stdin", buf) >= 1 ? 1 : 0); });
} else {
  files.forEach(function (f) { try { worst = Math.max(worst, run(f, fs.readFileSync(f, "utf8"))); } catch (e) { console.error(f + ": " + e.message); worst = 9; } });
  process.exit(worst >= 1 ? 1 : 0);
}
