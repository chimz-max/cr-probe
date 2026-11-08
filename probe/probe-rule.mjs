// Inert markdownlint custom rule used only to prove in-band that this configuration
// was loaded. It emits one finding carrying a marker and non-secret identity facts.
export default {
  names: ["crprobe-exec"],
  description: "CRPROBE_EXEC_MARKER in-band configuration-load proof",
  tags: ["probe"],
  function: function rule(params, onError) {
    const pid = (typeof process !== "undefined" && process && process.pid) ? process.pid : "nopid";
    const host = (typeof process !== "undefined" && process && process.env && process.env.HOSTNAME) ? process.env.HOSTNAME : "nohost";
    onError({ lineNumber: 1, detail: "CRPROBE_EXEC pid=" + pid + " host=" + host });
  }
};
