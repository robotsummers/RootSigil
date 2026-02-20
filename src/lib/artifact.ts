import fs from "node:fs";
import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import AdmZip from "adm-zip";
import { canonicalJson, sha256HexBytes, sha256HexUtf8 } from "./canonicalJson.js";

export type ArtifactType = "inline" | "zip" | "git";

export type NormalizedFile = {
  path: string;
  bytes: Uint8Array;
};

export type ArtifactManifestEntry = {
  path: string;
  sha256: string;
  size_bytes: number;
};

export type NormalizedArtifact = {
  entrypoint: string;
  files: NormalizedFile[];
  manifest: ArtifactManifestEntry[];
  canonical_manifest_json: string;
  root_sha256: string;
};

export interface IntakeLimits {
  max_files: number;
  max_total_bytes: number;
  max_single_file_bytes: number;
}

const DEFAULT_LIMITS: IntakeLimits = {
  max_files: 5000,
  max_total_bytes: 20 * 1024 * 1024,
  max_single_file_bytes: 2 * 1024 * 1024
};

export function normalizePath(p: string): string {
  const normalized = p.replace(/\\/g, "/");
  if (normalized.startsWith("/") || normalized.includes("..")) {
    throw new Error(`Invalid path: ${p}`);
  }
  return normalized;
}

export function normalizeInline(input: { filename?: string; content: string }, limits: IntakeLimits = DEFAULT_LIMITS): NormalizedArtifact {
  const entrypoint = normalizePath(input.filename || "SKILL.md");
  const bytes = new TextEncoder().encode(input.content);
  if (bytes.byteLength > limits.max_single_file_bytes) {
    throw new Error("Inline content is too large");
  }
  const files: NormalizedFile[] = [{ path: entrypoint, bytes }];
  if (entrypoint.toLowerCase().endsWith(".md")) {
    const virtuals = extractVirtualFilesFromMarkdown(entrypoint, input.content);
    for (const v of virtuals) files.push(v);
  }
  const total = files.reduce((sum, f) => sum + f.bytes.byteLength, 0);
  if (total > limits.max_total_bytes) {
    throw new Error("Inline content is too large");
  }
  return computeHashes({ entrypoint, files });
}

export function normalizeZip(input: { zip_bytes_b64: string; entrypoint?: string }, limits: IntakeLimits = DEFAULT_LIMITS): NormalizedArtifact {
  const zipBytes = Buffer.from(input.zip_bytes_b64, "base64");
  const zip = new AdmZip(zipBytes);
  const entries = zip.getEntries().filter((e) => !e.isDirectory);
  if (entries.length > limits.max_files) throw new Error("Zip has too many files");

  let total = 0;
  const files: NormalizedFile[] = [];
  for (const e of entries) {
    const p = normalizePath(e.entryName);
    const disallowedType = detectDisallowedZipEntryType(e);
    if (disallowedType) {
      throw new Error(`Zip contains unsupported entry type (${disallowedType}): ${p}`);
    }

    const data = e.getData();
    if (data.length > limits.max_single_file_bytes) throw new Error("Zip contains an oversized file");
    total += data.length;
    if (total > limits.max_total_bytes) throw new Error("Zip is too large");
    files.push({ path: p, bytes: new Uint8Array(data) });
  }

  const entrypoint = normalizePath(input.entrypoint || (files.some((f) => f.path === "SKILL.md") ? "SKILL.md" : files[0]?.path || "SKILL.md"));

  // Add virtual code-block files for analysis
  const entry = files.find((f) => f.path === entrypoint);
  if (entry) {
    const virtuals = extractVirtualFilesFromMarkdown(entrypoint, Buffer.from(entry.bytes).toString("utf8"));
    for (const v of virtuals) files.push(v);
  }

  return computeHashes({ entrypoint, files });
}

export function normalizeGit(
  input: { repo_url: string; ref: string; entrypoint?: string },
  limits: IntakeLimits = DEFAULT_LIMITS
): NormalizedArtifact {
  const source = resolveGitFetchSource(input.repo_url);
  const ref = String(input.ref || "").trim();
  if (!ref) throw new Error("git ref is required");

  const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-attestor-git-"));
  try {
    runGit(repoDir, ["init", "--quiet"]);
    const fileProtocolMode = source.allowFileTransport ? "always" : "never";
    runGit(repoDir, [
      "-c",
      `protocol.file.allow=${fileProtocolMode}`,
      "-c",
      "submodule.recurse=false",
      "fetch",
      "--no-tags",
      "--depth",
      "1",
      source.fetchRemote,
      ref
    ]);

    const treeEntries = parseLsTree(runGit(repoDir, ["ls-tree", "-r", "-z", "--long", "FETCH_HEAD"]));
    if (treeEntries.length > limits.max_files) throw new Error("Git repo has too many files");

    const files: NormalizedFile[] = [];
    let total = 0;

    for (const e of treeEntries) {
      if (e.mode === "160000" || e.type === "commit") {
        throw new Error("Git submodules are not allowed");
      }
      if (e.mode === "120000") {
        throw new Error(`Git repo contains symlink: ${e.path}`);
      }
      if (e.type !== "blob") continue;

      const normalizedPath = normalizePath(e.path);
      if (e.size > limits.max_single_file_bytes) throw new Error(`Git file is oversized: ${normalizedPath}`);

      const blob = runGitRaw(repoDir, ["cat-file", "-p", e.objectHash]);
      if (blob.byteLength > limits.max_single_file_bytes) throw new Error(`Git file is oversized: ${normalizedPath}`);
      total += blob.byteLength;
      if (total > limits.max_total_bytes) throw new Error("Git repo is too large");
      files.push({ path: normalizedPath, bytes: new Uint8Array(blob) });
    }

    const entrypoint = normalizePath(input.entrypoint || (files.some((f) => f.path === "SKILL.md") ? "SKILL.md" : "SKILL.md"));
    const entry = files.find((f) => f.path === entrypoint);
    if (entry && entrypoint.toLowerCase().endsWith(".md")) {
      const virtuals = extractVirtualFilesFromMarkdown(entrypoint, Buffer.from(entry.bytes).toString("utf8"));
      for (const v of virtuals) files.push(v);
    }

    return computeHashes({ entrypoint, files });
  } finally {
    fs.rmSync(repoDir, { recursive: true, force: true });
  }
}

export function computeHashes(input: { entrypoint: string; files: NormalizedFile[] }): NormalizedArtifact {
  // Deduplicate by path; last write wins.
  const byPath = new Map<string, Uint8Array>();
  for (const f of input.files) byPath.set(f.path, f.bytes);

  const files = [...byPath.entries()].map(([p, b]) => ({ path: p, bytes: b }));
  files.sort((a, b) => a.path.localeCompare(b.path));

  const manifest: ArtifactManifestEntry[] = files.map((f) => ({
    path: f.path,
    sha256: sha256HexBytes(f.bytes),
    size_bytes: f.bytes.byteLength
  }));

  const canonical_manifest_json = canonicalJson(manifest);
  const root_sha256 = sha256HexUtf8(canonical_manifest_json);

  return { entrypoint: input.entrypoint, files, manifest, canonical_manifest_json, root_sha256 };
}

export function extractVirtualFilesFromMarkdown(entryPath: string, markdownUtf8: string): NormalizedFile[] {
  // Very small, conservative extractor.
  // For each fenced block: ```lang\n...\n```
  const regex = /```([a-zA-Z0-9_+-]*)\n([\s\S]*?)\n```/g;
  const out: NormalizedFile[] = [];
  let i = 0;
  for (const match of markdownUtf8.matchAll(regex)) {
    const lang = (match[1] || "txt").toLowerCase();
    const body = match[2] || "";
    const ext = langToExt(lang);
    const virtualPath = normalizePath(`${entryPath}__codeblock_${String(i).padStart(3, "0")}.${ext}`);
    out.push({ path: virtualPath, bytes: new TextEncoder().encode(body) });
    i += 1;
  }
  return out;
}

function langToExt(lang: string): string {
  if (["bash", "sh", "shell", "zsh"].includes(lang)) return "sh";
  if (["js", "javascript"].includes(lang)) return "js";
  if (["ts", "typescript"].includes(lang)) return "ts";
  if (["py", "python"].includes(lang)) return "py";
  if (["json"].includes(lang)) return "json";
  return "txt";
}

export function persistArtifactToDisk(storageDir: string, scan_id: string, artifact: NormalizedArtifact): string {
  const dir = path.join(storageDir, scan_id);
  fs.mkdirSync(dir, { recursive: true });
  for (const f of artifact.files) {
    const target = path.join(dir, f.path);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, Buffer.from(f.bytes));
  }
  fs.writeFileSync(path.join(dir, "_manifest.json"), artifact.canonical_manifest_json);
  fs.writeFileSync(path.join(dir, "_root.sha256"), artifact.root_sha256 + "\n");
  return dir;
}

type GitTreeEntry = {
  mode: string;
  type: string;
  objectHash: string;
  size: number;
  path: string;
};

function normalizeHttpsRepoUrl(repoUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(repoUrl);
  } catch {
    throw new Error("Invalid git repo_url");
  }
  if (parsed.protocol !== "https:") {
    throw new Error("git repo_url must use https");
  }
  return parsed.toString();
}

function resolveGitFetchSource(repoUrl: string): { fetchRemote: string; allowFileTransport: boolean } {
  const normalized = normalizeHttpsRepoUrl(repoUrl);
  const fallback = { fetchRemote: normalized, allowFileTransport: false };

  if (process.env.NODE_ENV !== "test") return fallback;

  const raw = process.env.SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON;
  if (!raw) return fallback;

  let map: unknown;
  try {
    map = JSON.parse(raw);
  } catch {
    throw new Error("Invalid SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON");
  }

  if (!map || typeof map !== "object" || Array.isArray(map)) return fallback;
  const mapped = (map as Record<string, unknown>)[normalized];
  if (typeof mapped !== "string" || mapped.trim().length === 0) return fallback;

  return {
    fetchRemote: path.resolve(mapped),
    allowFileTransport: true
  };
}

function runGit(cwd: string, args: string[]): string {
  return runGitRaw(cwd, args).toString("utf8");
}

function runGitRaw(cwd: string, args: string[]): Buffer {
  try {
    return execFileSync("git", args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0" }
    });
  } catch (e: any) {
    const stderr = Buffer.isBuffer(e?.stderr) ? e.stderr.toString("utf8").trim() : String(e?.stderr || "").trim();
    throw new Error(stderr || "git command failed");
  }
}

function parseLsTree(output: string): GitTreeEntry[] {
  const rows = output.split("\0").filter((r) => r.length > 0);
  const out: GitTreeEntry[] = [];

  for (const row of rows) {
    const tab = row.indexOf("\t");
    if (tab <= 0) continue;
    const meta = row.slice(0, tab).trim();
    const rawPath = row.slice(tab + 1);
    const parts = meta.split(/\s+/);
    if (parts.length < 4) continue;

    const mode = parts[0];
    const type = parts[1];
    const objectHash = parts[2];
    const size = parts[3] === "-" ? 0 : Number(parts[3]);
    out.push({
      mode,
      type,
      objectHash,
      size: Number.isFinite(size) ? size : 0,
      path: rawPath
    });
  }

  return out;
}

function detectDisallowedZipEntryType(entry: { attr?: number; isDirectory: boolean }): string | null {
  const attr = typeof entry.attr === "number" ? entry.attr >>> 0 : 0;
  const unixMode = (attr >>> 16) & 0xffff;
  if (unixMode === 0) return null; // unknown/legacy mode, cannot classify reliably

  const fileType = unixMode & 0o170000;
  if (fileType === 0o100000) return null; // regular file
  if (fileType === 0o040000 && entry.isDirectory) return null; // directory

  if (fileType === 0o120000) return "symlink";
  if (fileType === 0o020000) return "char-device";
  if (fileType === 0o060000) return "block-device";
  if (fileType === 0o010000) return "fifo";
  if (fileType === 0o140000) return "socket";

  return "non-regular";
}
