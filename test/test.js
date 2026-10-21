"use strict";
var assert = require("assert"), P = require("../php2shell-check.js"), ok = 0;
function st(text) { return P.analyze(text).rows.map(function (r) { return r.st + ":" + r.find.sapi; }); }
function eq(a, b) { assert.deepStrictEqual(a, b); ok++; }
eq(st("FROM php:8.1-apache"), ["eolbackport:modphp"]);
eq(st("FROM php:8.3.11-fpm"), ["vulnerable:fpm"]);
eq(st("FROM php:8.3.36-fpm"), ["fixed:fpm"]);
eq(st("FROM php:8.4-cli"), ["pull:cli"]);
eq(st("    image: wordpress:6.6-php8.2-apache"), ["pull:modphp"]);
eq(st("PHP 8.4.27 (cli) (built: Oct 21 2026)"), ["fixed:cli"]);
eq(st("PHP 8.2.34 (fpm-fcgi) (built: Sep 24 2026)"), ["vulnerable:fpm"]);
eq(st("PHP 8.3.6-0ubuntu0.24.04.5 (cli)"), ["vendor:cli"]);
eq(st("PHP Version => 8.2.20\nServer API => Apache 2.0 Handler"), ["vulnerable:modphp"]);
eq(st("x-powered-by: PHP/5.6.40"), ["eolnone:web"]);
eq(st("ii  libapache2-mod-php8.1  8.1.2-1ubuntu2.19  amd64  module"), ["vendor:modphp"]);
eq(st("      php-version: '8.1'"), ["eolbackport:ci"]);
eq(st('{"require": {"php": "^8.1"}}'), ["info:req"]);
eq(st("PHP 8.6.0RC3 (cli)"), ["vulnerable:cli"]);
eq(st("PHP 8.6.0RC4 (cli)"), ["fixed:cli"]);
eq(st("FROM node:20\nFROM mysql:8"), []);
assert.strictEqual(P.analyze("FROM php:8.1-apache").rows[0].fix, "php:8.4-apache  →  php:8.4.27-apache"); ok++;
console.log(ok + " checks passed");
