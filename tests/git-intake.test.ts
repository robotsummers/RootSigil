import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { normalizeGit } from "../src/lib/artifact.js";

const originalRewriteMap = process.env.SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON;
const originalNodeEnv = process.env.NODE_ENV;
const tmpDirs: string[] = [];

afterEach(() => {
  if (originalRewriteMap === undefined) {
    delete process.env.SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON;
  } else {
    process.env.SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON = originalRewriteMap;
  }

  if (originalNodeEnv === undefined) {
    delete process.env.NODE_ENV;
  } else {
    process.env.NODE_ENV = originalNodeEnv;
  }

  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("git intake", () => {
  test("rejects non-https repository URLs", () => {
    expect(() =>
      normalizeGit({
        repo_url: "file:///tmp/repo",
        ref: "main"
      })
    ).toThrow(/https/i);
  });

  test("requires a non-empty git ref", () => {
    expect(() =>
      normalizeGit({
        repo_url: "https://example.com/repo.git",
        ref: "   "
      })
    ).toThrow(/ref/i);
  });

  test("rejects git submodule entries (mode 160000)", () => {
    const repoDir = createGitRepo({
      "README.md": "fixture"
    });
    const commitHash = runGit(repoDir, ["rev-parse", "HEAD"]).trim();
    runGit(repoDir, ["update-index", "--add", "--cacheinfo", `160000,${commitHash},deps/submodule`]);
    runGit(repoDir, ["commit", "-m", "add gitlink entry"]);

    const repoUrl = "https://example.com/submodule-fixture.git";
    useGitRewriteMap({ [repoUrl]: repoDir });
    expect(() => normalizeGit({ repo_url: repoUrl, ref: "HEAD" })).toThrow(/submodule/i);
  });

  test("rejects git symlink entries (mode 120000)", () => {
    const repoDir = createEmptyGitRepo();
    const targetBlob = runGit(repoDir, ["hash-object", "-w", "--stdin"], "target-path\n").trim();
    runGit(repoDir, ["update-index", "--add", "--cacheinfo", `120000,${targetBlob},link-to-target`]);
    runGit(repoDir, ["commit", "-m", "add symlink entry"]);

    const repoUrl = "https://example.com/symlink-fixture.git";
    useGitRewriteMap({ [repoUrl]: repoDir });
    expect(() => normalizeGit({ repo_url: repoUrl, ref: "HEAD" })).toThrow(/symlink/i);
  });

  test("enforces git max_files limit", () => {
    const repoDir = createGitRepo({
      "a.txt": "one",
      "b.txt": "two",
      "c.txt": "three"
    });
    const repoUrl = "https://example.com/max-files-fixture.git";
    useGitRewriteMap({ [repoUrl]: repoDir });

    expect(() =>
      normalizeGit(
        {
          repo_url: repoUrl,
          ref: "HEAD"
        },
        {
          max_files: 2,
          max_total_bytes: 1024 * 1024,
          max_single_file_bytes: 1024 * 1024
        }
      )
    ).toThrow(/too many files/i);
  });
});

function useGitRewriteMap(map: Record<string, string>): void {
  process.env.NODE_ENV = "test";
  process.env.SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON = JSON.stringify(map);
}

function createGitRepo(files: Record<string, string>): string {
  const repoDir = createEmptyGitRepo();
  for (const [relativePath, contents] of Object.entries(files)) {
    const targetPath = path.join(repoDir, relativePath);
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, contents, "utf8");
  }
  runGit(repoDir, ["add", "."]);
  runGit(repoDir, ["commit", "-m", "fixture commit"]);
  return repoDir;
}

function createEmptyGitRepo(): string {
  const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-attestor-git-intake-"));
  tmpDirs.push(repoDir);
  runGit(repoDir, ["init"]);
  runGit(repoDir, ["config", "user.name", "Test User"]);
  runGit(repoDir, ["config", "user.email", "test@example.com"]);
  return repoDir;
}

function runGit(cwd: string, args: string[], input?: string): string {
  return execFileSync("git", args, {
    cwd,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
    input
  }).toString("utf8");
}
