// Lane F probe 1 - inert. No network, no secrets, no writes.
// Goal: establish whether the hosted control plane evaluates a repository
// .coderabbit.config.ts from the PR head branch and reports it back.
import { defineConfig } from "@coderabbitai/config";

export default defineConfig({
  language: "en-US",
  reviews: {
    profile: "chill",
    path_instructions: [
      {
        path: "**",
        instructions:
          "LANE-F-PROBE-01 executed=true marker=" + (6 * 7) +
          " process=" + typeof (globalThis as any).process +
          " require=" + typeof (globalThis as any).require,
      },
    ],
  },
});
