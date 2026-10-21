/* PHP2Shell Check core. Reads php -v, phpinfo, headers, Dockerfiles, compose files, CI configs and package lists,
   and says which PHP installs need the October 2026 fix for CVE-2026-109618 and CVE-2026-109619.
   Defensive only. It reads text you paste, nothing is sent anywhere.
   MIT License. https://github.com/guoziyu415/php2shell-check */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.P2S = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // From the PHP security advisory of 2026-10-21 (php.net).
  var FIXED = { "8.5": 12, "8.4": 27, "8.3": 36, "8.2": 35 };
  var BACKPORT = { "7.4": 1, "8.0": 1, "8.1": 1 }; // official minimal source backports only, no release
  var FIXED_RC_86 = 4; // PHP 8.6.0 RC4 contains the fixes
  var LATEST = "8.5";

  var SAPI = {
    modphp: { risk: 3, ja: "Apache の mod_php", en: "Apache mod_php" },
    fpm: { risk: 2, ja: "PHP-FPM", en: "PHP-FPM" },
    cgi: { risk: 2, ja: "php-cgi", en: "php-cgi" },
    frankenphp: { risk: 2, ja: "FrankenPHP", en: "FrankenPHP" },
    litespeed: { risk: 2, ja: "LiteSpeed", en: "LiteSpeed" },
    web: { risk: 2, ja: "Web で動く PHP（方式は不明）", en: "PHP serving web requests, mode unknown" },
    unknown: { risk: 2, ja: "動かし方は不明", en: "mode unknown" },
    cli: { risk: 1, ja: "CLI（Web を処理しない）", en: "CLI, not serving web requests" },
    ci: { risk: 1, ja: "CI のテスト用", en: "CI tests" },
    req: { risk: 0, ja: "composer の動作条件", en: "composer requirement" }
  };

  function cmpPatch(branch, patch) { return FIXED[branch] !== undefined ? (patch >= FIXED[branch] ? "fixed" : "vulnerable") : null; }

  // Decide the status of one PHP version.
  // v = {major, minor, patch (number or null), rc (number or null), distro (string or null), floating (bool)}
  function judge(v) {
    var branch = v.major + "." + v.minor;
    var num = v.major * 100 + v.minor;
    if (v.major === 8 && v.minor === 6) {
      if (v.rc !== null && v.rc !== undefined && v.rc >= FIXED_RC_86) return { st: "fixed", branch: branch, target: "8.6.0RC" + FIXED_RC_86 };
      return { st: "vulnerable", branch: branch, target: "8.6.0RC" + FIXED_RC_86, pre: true };
    }
    if (FIXED[branch] !== undefined) {
      var target = branch + "." + FIXED[branch];
      if (v.floating) return { st: "pull", branch: branch, target: target };
      if (v.patch === null || v.patch === undefined) return { st: "unknownpatch", branch: branch, target: target };
      if (v.distro) return { st: v.patch >= FIXED[branch] ? "fixed" : "vendor", branch: branch, target: target };
      return { st: cmpPatch(branch, v.patch), branch: branch, target: target };
    }
    if (BACKPORT[branch]) return { st: v.distro ? "vendor" : "eolbackport", branch: branch, target: "8.4.27" };
    if (num > 805) return { st: "unknownpatch", branch: branch, target: LATEST + "." + FIXED[LATEST] };
    return { st: v.distro ? "vendor" : "eolnone", branch: branch, target: "8.4.27" };
  }

  var ST = {
    fixed: { level: 0, ja: "修正済み", en: "Fixed" },
    pull: { level: 1, ja: "取り直しが必要", en: "Pull and rebuild" },
    vendor: { level: 2, ja: "ディストリの対応を確認", en: "Check your vendor" },
    unknownpatch: { level: 2, ja: "パッチ番号を確認", en: "Check the exact version" },
    vulnerable: { level: 3, ja: "要アップデート", en: "Update now" },
    eolbackport: { level: 4, ja: "サポート終了・公式版なし", en: "End of life, no release" },
    eolnone: { level: 4, ja: "サポート終了・修正なし", en: "End of life, no fix" },
    info: { level: 0, ja: "参考", en: "Info" }
  };

  function pv(s) {
    var m = /^(\d+)\.(\d+)(?:\.(\d+))?(?:\.?(?:RC|rc)(\d+))?/.exec(s || "");
    if (!m) return null;
    return { major: +m[1], minor: +m[2], patch: m[3] !== undefined ? +m[3] : null, rc: m[4] !== undefined ? +m[4] : null };
  }

  function lineOf(text, idx) { while (idx < text.length && /\s/.test(text[idx])) idx++; return text.slice(0, idx).split("\n").length; }

  var IMG_VARIANT = function (tag) {
    tag = (tag || "").toLowerCase();
    if (/apache/.test(tag)) return "modphp";
    if (/fpm/.test(tag)) return "fpm";
    if (/frankenphp/.test(tag)) return "frankenphp";
    if (/litespeed|lsphp/.test(tag)) return "litespeed";
    if (/cli/.test(tag)) return "cli";
    if (/zts/.test(tag)) return "cli";
    return null;
  };

  // Each finder returns {kind, line, raw, v, sapi, note, image}
  function scan(text) {
    var out = [], m, re;
    text = String(text || "");

    // php -v first line, e.g. "PHP 8.1.2-1ubuntu2.19 (cli) (built: ...)"
    re = /\bPHP (\d+\.\d+\.\d+(?:RC\d+)?)([^\s(]*)\s*\((cli|fpm-fcgi|cgi-fcgi|apache2handler|litespeed|frankenphp|embed|phpdbg)\)/gi;
    while ((m = re.exec(text))) {
      var v = pv(m[1]); var suf = m[2] || "";
      v.distro = /ubuntu|deb|el\d|fc\d|\+|~|sury|remi|alpine|-r\d/i.test(suf) ? suf.replace(/^[-+~]/, "") : null;
      var s = { cli: "cli", "fpm-fcgi": "fpm", "cgi-fcgi": "cgi", apache2handler: "modphp", litespeed: "litespeed", frankenphp: "frankenphp", embed: "unknown", phpdbg: "cli" }[m[3].toLowerCase()];
      out.push({ kind: "phpv", line: lineOf(text, m.index), raw: m[0], v: v, sapi: s,
        note: s === "cli" ? "php -v は CLI の版を表示します。Web 側の PHP-FPM や mod_php が同じ版かも確かめてください。" : null,
        noteEn: s === "cli" ? "php -v shows the CLI build. Check that the PHP behind your web server is the same version." : null });
    }

    // phpinfo text or HTML-stripped table
    re = /PHP Version\s*(?:=>|:)?\s*(\d+\.\d+\.\d+(?:RC\d+)?)([^\s<]*)/gi;
    while ((m = re.exec(text))) {
      var v2 = pv(m[1]); var suf2 = m[2] || "";
      v2.distro = /ubuntu|deb|el\d|fc\d|\+|~|sury|remi/i.test(suf2) ? suf2.replace(/^[-+~]/, "") : null;
      var api = /Server API\s*(?:=>|:)?\s*([^\n<]+)/i.exec(text.slice(m.index, m.index + 4000));
      var s2 = "web";
      if (api) {
        var a = api[1].toLowerCase();
        s2 = /apache 2\.0 handler|apache2handler/.test(a) ? "modphp" : /fpm/.test(a) ? "fpm" : /cgi/.test(a) ? "cgi" : /litespeed/.test(a) ? "litespeed" : /frankenphp/.test(a) ? "frankenphp" : /command line/.test(a) ? "cli" : "web";
      }
      out.push({ kind: "phpinfo", line: lineOf(text, m.index), raw: m[0] + (api ? "  Server API " + api[1].trim() : ""), v: v2, sapi: s2 });
    }

    // HTTP header
    re = /X-Powered-By:\s*PHP\/(\d+\.\d+(?:\.\d+)?)([^\s,]*)/gi;
    while ((m = re.exec(text))) {
      var v3 = pv(m[1]); var suf3 = m[2] || "";
      v3.distro = /ubuntu|deb|el\d|\+|~/i.test(suf3) ? suf3.replace(/^[-+~]/, "") : null;
      out.push({ kind: "header", line: lineOf(text, m.index), raw: m[0], v: v3, sapi: "web",
        note: "X-Powered-By で版が外から見えています。expose_php = Off で隠せますが、隠しても脆弱性は残ります。",
        noteEn: "Your PHP version is visible from outside. expose_php = Off hides it, but hiding does not fix anything." });
    }

    // Container images in Dockerfiles, compose files, k8s manifests
    re = /(?:^|\n)\s*(?:FROM(?:\s+--platform=\S+)?\s+|-?\s*image:\s*["']?)((?:[\w.-]+(?::\d+)?\/)*[\w.-]+)(?::([\w.-]+))?(?:@sha256:[a-f0-9]+)?/gi;
    while ((m = re.exec(text))) {
      var name = m[1].toLowerCase().replace(/^(docker\.io\/)?(library\/)?/, "");
      var tag = (m[2] || "latest").toLowerCase();
      var at = lineOf(text, m.index + m[0].indexOf(m[1]));
      var raw = m[0].trim();
      var phpVer = null, sapi = null, floating = false, imageKind = null;
      if (name === "php") {
        imageKind = "php";
        var tv = /^(\d+(?:\.\d+){0,2}(?:rc\d+)?)/.exec(tag);
        if (tv) {
          var parts = tv[1].split(".");
          if (parts.length === 1) { phpVer = { major: +parts[0], minor: +parts[0] === 8 ? 5 : 4, patch: null, rc: null }; floating = true; }
          else { phpVer = pv(tv[1]); if (phpVer.patch === null && phpVer.rc === null) floating = true; }
        } else { phpVer = { major: 8, minor: 5, patch: null, rc: null }; floating = true; }
        sapi = IMG_VARIANT(tag) || "cli";
      } else if (/(^|\/)(wordpress|drupal|joomla|nextcloud|matomo|mediawiki|magento|prestashop|phpmyadmin|moodle|wordpress-fpm)$/.test(name) || /(^|\/)(php|php-fpm|frankenphp|php-apache|php-nginx)$/.test(name) || /php/.test(name)) {
        imageKind = "app";
        var pm = /php-?(\d)\.?(\d)(?:\.(\d+))?/.exec(tag) || /^(\d)\.(\d)(?:\.(\d+))?/.exec(tag);
        if (pm && (/php/.test(name) || /php/.test(tag))) { phpVer = { major: +pm[1], minor: +pm[2], patch: pm[3] !== undefined ? +pm[3] : null, rc: null }; floating = pm[3] === undefined; }
        sapi = /frankenphp/.test(name + tag) ? "frankenphp" : IMG_VARIANT(tag) || (/fpm/.test(name) ? "fpm" : /apache/.test(name) ? "modphp" : /^(wordpress|drupal|joomla|nextcloud|matomo|mediawiki|phpmyadmin)$/.test(name) ? "modphp" : "web");
      } else continue;
      out.push({ kind: "image", line: at, raw: raw, image: name + ":" + tag, imageName: name, imageTag: tag, imageKind: imageKind, v: phpVer ? Object.assign(phpVer, { floating: floating, distro: null }) : null, sapi: sapi });
    }

    // Debian and Ubuntu package lists (dpkg -l, apt list) and RPM names
    re = /(?:^|\n)\s*(?:ii\s+)?(libapache2-mod-php|php)(\d\.\d)(-fpm|-cgi|-cli|-common|-litespeed)?(?::\w+)?(?:\/[\w,.-]+)?\s+(\d+:)?(\d+\.\d+\.\d+)([-~+][\w.~+:-]*)/gi;
    while ((m = re.exec(text))) {
      var v4 = pv(m[5]); v4.distro = (m[6] || "").replace(/^[-~+]/, "") || "package";
      var s4 = /mod-php/.test(m[1]) ? "modphp" : m[3] === "-fpm" ? "fpm" : m[3] === "-cgi" ? "cgi" : m[3] === "-cli" ? "cli" : m[3] === "-litespeed" ? "litespeed" : "unknown";
      out.push({ kind: "package", line: lineOf(text, m.index), raw: m[0].trim(), v: v4, sapi: s4 });
    }
    re = /(?:^|\n)\s*(php(?:-fpm|-cli|-common)?)-(\d+\.\d+\.\d+)-([\w.]+(?:el|fc|amzn)\d[\w.]*)/gi;
    while ((m = re.exec(text))) {
      var v5 = pv(m[2]); v5.distro = m[3];
      out.push({ kind: "package", line: lineOf(text, m.index), raw: m[0].trim(), v: v5, sapi: /fpm/.test(m[1]) ? "fpm" : /cli/.test(m[1]) ? "cli" : "unknown" });
    }

    // GitHub Actions setup-php and CI matrices
    re = /(?:^|\n)[ \t-]*(?:php-version|php-versions|php)\s*:\s*\[?\s*((?:["']?\d\.\d+(?:\.\d+)?["']?\s*,?\s*)+)\]?/gi;
    while ((m = re.exec(text))) {
      var vs = m[1].match(/\d\.\d+(?:\.\d+)?/g) || [];
      for (var k = 0; k < vs.length; k++) {
        var v6 = pv(vs[k]); v6.floating = v6.patch === null; v6.distro = null;
        out.push({ kind: "ci", line: lineOf(text, m.index), raw: m[0].trim().slice(0, 60), v: v6, sapi: "ci" });
      }
    }

    // composer.json requirement
    re = /"php"\s*:\s*"([^"]+)"/gi;
    while ((m = re.exec(text))) {
      var mv = /(\d)\.(\d+)/.exec(m[1]);
      if (!mv) continue;
      out.push({ kind: "composer", line: lineOf(text, m.index), raw: m[0], v: { major: +mv[1], minor: +mv[2], patch: null, rc: null, floating: true, distro: null }, sapi: "req" });
    }

    // Plain "PHP 8.1.27" or "php 7.4" mentions in a server list, if nothing above matched that line
    re = /(?:^|\n)([^\n]*?)\bPHP[ /]?(\d+\.\d+(?:\.\d+)?)\b([^\n]*)/gi;
    var taken = {};
    out.forEach(function (o) { taken[o.line] = 1; });
    while ((m = re.exec(text))) {
      var ln = lineOf(text, m.index + (m[0][0] === "\n" ? 1 : 0));
      if (taken[ln]) continue;
      var v7 = pv(m[2]); v7.distro = null; v7.floating = v7.patch === null;
      var ctx = (m[1] + " " + m[3]).toLowerCase();
      var s7 = /mod_php|apache/.test(ctx) ? "modphp" : /fpm/.test(ctx) ? "fpm" : /cgi/.test(ctx) ? "cgi" : /frankenphp/.test(ctx) ? "frankenphp" : /litespeed/.test(ctx) ? "litespeed" : /\bcli\b/.test(ctx) ? "cli" : "unknown";
      out.push({ kind: "list", line: ln, raw: m[0].trim().slice(0, 90), v: v7, sapi: s7 });
      taken[ln] = 1;
    }
    out.sort(function (a, b) { return a.line - b.line; });
    return out;
  }

  function imageFix(f, j) {
    if (!f.image) return null;
    if (f.imageKind === "php") {
      var rest = f.imageTag.replace(/^\d+(?:\.\d+){0,2}(?:rc\d+)?-?/, "");
      if (f.imageTag === "latest" || /^[a-z]/.test(f.imageTag)) return "php:" + j.target + (rest && f.imageTag !== "latest" ? "-" + rest : "");
      if (j.st === "eolbackport" || j.st === "eolnone") return "php:8.4" + (rest ? "-" + rest : "") + "  →  " + "php:8.4.27" + (rest ? "-" + rest : "");
      return "php:" + j.target + (rest ? "-" + rest : "");
    }
    return null;
  }

  function analyze(text) {
    var finds = scan(text);
    var rows = finds.map(function (f) {
      var j = f.v ? judge(f.v) : { st: "unknownpatch", branch: "?", target: LATEST + "." + FIXED[LATEST] };
      if (f.sapi === "req") j = { st: "info", branch: j.branch, target: j.target, oldOk: !!(f.v && (f.v.major < 8 || (f.v.major === 8 && f.v.minor <= 1))) };
      var risk = SAPI[f.sapi] ? SAPI[f.sapi].risk : 2;
      return { find: f, judge: j, st: j.st, level: ST[j.st].level, risk: risk, fix: imageFix(f, j) };
    });
    var worst = rows.reduce(function (a, r) { return r.find.sapi === "req" || r.find.sapi === "ci" ? a : Math.max(a, r.level); }, -1);
    var counts = {};
    rows.forEach(function (r) { counts[r.st] = (counts[r.st] || 0) + 1; });
    return { rows: rows, worst: worst, counts: counts };
  }

  // Human text for one row, in Japanese or English.
  function explain(r, lang) {
    var f = r.find, j = r.judge, ja = lang !== "en", L = [];
    var ver = f.v ? f.v.major + "." + f.v.minor + (f.v.patch !== null && f.v.patch !== undefined ? "." + f.v.patch : "") + (f.v.rc ? "RC" + f.v.rc : "") : "?";
    var sapi = SAPI[f.sapi] || SAPI.unknown;
    var head = (f.image ? f.image : "PHP " + ver) + (f.image && f.v ? "  ·  PHP " + ver + (f.v.floating ? ".x" : "") : "");
    switch (r.st) {
      case "fixed":
        L.push(ja ? "修正版です。" + (f.v && f.v.distro ? "ディストリの番号も修正版以上です。" : "") : "This is a fixed version.");
        break;
      case "pull":
        if (f.imageKind === "app") { L.push(ja ? "このイメージは中の PHP " + j.branch + " を公式イメージから引き継ぎます。修正版の PHP で作り直されたものを pull してコンテナを入れ替え、中で php -v を実行して " + j.target + " 以上か確かめてください。" : "This image inherits PHP " + j.branch + " from its base. Pull the rebuilt image, replace the containers, and run php -v inside to confirm " + j.target + " or newer."); break; }
        if (f.sapi === "ci") { L.push(ja ? "CI は実行のたびに最新の " + j.branch + " を入れることが多いので、ログの php -v が " + j.target + " 以上か見てください。" : "CI usually installs the latest " + j.branch + " on each run. Check that php -v in the log shows " + j.target + " or newer."); break; }
        var pin = r.fix ? String(r.fix).split(/\s+/).pop() : "";
        L.push(ja ? "このタグは Docker Hub で修正版 " + j.target + " に切り替わりました。ただし手元のイメージと動いているコンテナは古いままなので、pull して再ビルドし、コンテナを入れ替えてください。最後にコンテナの中で php -v を実行して " + j.target + " 以上か確かめると確実です。" + (pin ? pin + " のように版まで固定しておくと、どの版が入るかがはっきりします。" : "") : "This tag now points to the fixed " + j.target + " on Docker Hub. Your cached image and running containers are still old, so pull, rebuild and replace the containers, then run php -v inside to confirm " + j.target + " or newer." + (pin ? " Pinning the exact tag, " + pin + ", makes the version explicit." : ""));
        break;
      case "vendor":
        L.push(ja ? "ディストリのパッケージです（" + f.v.distro + "）。ディストリには事前にパッチが渡っているので、OS の更新を確認して入れ、" + (f.sapi === "modphp" ? "Apache" : f.sapi === "fpm" ? "php-fpm" : "Web サーバー") + " を再起動してください。番号の見方はディストリのセキュリティ情報で確認できます。" : "This is a distribution package (" + f.v.distro + "). Vendors received the patches in advance, so install the OS update, restart " + (f.sapi === "modphp" ? "Apache" : f.sapi === "fpm" ? "php-fpm" : "the web server") + ", and confirm the fixed package version in your vendor's security tracker.");
        break;
      case "unknownpatch":
        L.push(ja ? "パッチ番号まで分かりません。" + j.branch + " 系なら " + j.target + " 以上か確かめてください。" : "The patch number is not visible. On " + j.branch + " you need " + j.target + " or newer.");
        break;
      case "vulnerable":
        L.push(ja ? (j.pre ? "8.6 のプレリリースです。" + j.target + " 以降に修正が入っています。" : j.target + " に上げてください。同じ " + j.branch + " 系なので互換性の心配は小さいはずです。") : (j.pre ? "PHP 8.6 pre-release. The fix is in " + j.target + "." : "Update to " + j.target + ". Same " + j.branch + " branch, so it should be a drop in update."));
        break;
      case "eolbackport":
        L.push(ja ? j.branch + " はサポート終了で、PHP 公式の修正版は出ません。公式が出したのはソースへの最小限のバックポートだけです。ディストリや LTS ベンダーの修正を使うか、8.4 か 8.5 に上げてください。" : j.branch + " is end of life, so there is no official release. The PHP team only published minimal source backports. Use a vendor fix or move to 8.4 or 8.5.");
        break;
      case "info":
        L.push(ja ? "composer の動作条件 " + f.raw.replace(/^"php"\s*:\s*/, "") + " です。" + (j.oldOk ? "サポート終了の 8.1 以前も許しているので、本番がどの版か確かめてください。" : "") : "Composer requirement " + f.raw.replace(/^"php"\s*:\s*/, "") + "." + (j.oldOk ? " It still allows end of life versions, so check what production runs." : ""));
        break;
      case "eolnone":
        L.push(ja ? j.branch + " は古すぎて、バックポートもありません。8.4 か 8.5 へ上げるまで、インターネットから切り離すのが安全です。" : j.branch + " is too old even for the backports. Move to 8.4 or 8.5, and keep it off the internet until then.");
        break;
    }
    if (f.sapi === "modphp" && r.st !== "fixed") L.push(ja ? "Apache の mod_php は公式が最も危険と見ている方式で、認証なしのリクエスト1つでアプリのコードより先に攻撃が成立することが実証されています。" : "PHP rates mod_php the highest risk, with a demonstrated attack from one unauthenticated request before any application code runs.");
    if ((f.sapi === "cli" || f.sapi === "ci") && r.st !== "fixed") L.push(ja ? "Web リクエストを処理しない使い方なら直接の危険は小さいですが、同じ版で Web を動かしていないか確認を。" : "Not serving web requests, so the direct risk is low. Make sure nothing serves the web with the same build.");
    if (f.sapi === "req") L.push(ja ? "実際に動いている版ではないので、本番の php -v を貼ると判定できます。" : "It is not the running version. Paste php -v from production to check it.");
    if (f.note) L.push(ja ? f.note : f.noteEn);
    return { head: head, sapi: sapi[ja ? "ja" : "en"], text: L.join(" ") };
  }

  return { scan: scan, analyze: analyze, judge: judge, explain: explain, ST: ST, SAPI: SAPI, FIXED: FIXED, version: "1.0.0" };
});
