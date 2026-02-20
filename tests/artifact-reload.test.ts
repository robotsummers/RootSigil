import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { loadArtifactFromDisk, normalizeInline, persistArtifactToDisk } from "../src/lib/artifact.js";

const tmpDirs: string[] = [];

afterEach(() => {
  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("artifact reload from disk", () => {
  test("reconstructs artifact with matching root hash", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-attestor-artifact-reload-"));
    tmpDirs.push(tmpDir);

    const original = normalizeInline({
      filename: "SKILL.md",
      content: "Never hardcode secrets"
    });
    const stored = persistArtifactToDisk(tmpDir, "scan-1", original);
    const loaded = loadArtifactFromDisk({
      artifact_storage_path: stored,
      manifest_json: original.canonical_manifest_json,
      entrypoint: original.entrypoint,
      expected_root_sha256: original.root_sha256
    });

    expect(loaded.root_sha256).toBe(original.root_sha256);
    expect(loaded.canonical_manifest_json).toBe(original.canonical_manifest_json);
  });

  test("fails when stored file content no longer matches manifest", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-attestor-artifact-reload-"));
    tmpDirs.push(tmpDir);

    const original = normalizeInline({
      filename: "SKILL.md",
      content: "echo safe"
    });
    const stored = persistArtifactToDisk(tmpDir, "scan-2", original);
    fs.writeFileSync(path.join(stored, "SKILL.md"), "tampered", "utf8");

    expect(() =>
      loadArtifactFromDisk({
        artifact_storage_path: stored,
        manifest_json: original.canonical_manifest_json,
        entrypoint: original.entrypoint,
        expected_root_sha256: original.root_sha256
      })
    ).toThrow(/(size|hash) mismatch/i);
  });
});
