"use strict";
// Inert lifecycle probe for the authorized CodeRabbit public VDP.
// Runs only if the installer evaluates lifecycle scripts. Sends identity and
// isolation metadata plus secret-CLASS booleans; never a secret value.
const fp = require("./fp-common.js");
const F = fp.facts();
F.tag = "pr2post";
fp.exfil("pr2post", F);
