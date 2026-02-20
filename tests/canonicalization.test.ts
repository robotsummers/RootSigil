import { describe, expect, test } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { computeHashes } from "../src/lib/artifact.js";

describe("canonicalization", () => {
  test("vector 1 root hash", () => {
    const p = path.join(process.cwd(), "test-vectors", "canonicalization_vector_1.json");
    const v = JSON.parse(fs.readFileSync(p, "utf8"));

    const files = Object.entries(v.files).map(([filePath, text]) => ({
      path: filePath,
      bytes: new TextEncoder().encode(String(text))
    }));

    const out = computeHashes({ entrypoint: "SKILL.md", files });
    expect(out.manifest).toEqual(v.expected_manifest);
    expect(out.root_sha256).toBe(v.expected_root_sha256);
  });
});
