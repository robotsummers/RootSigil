import AdmZip from "adm-zip";
import { describe, expect, test } from "vitest";
import { normalizeZip } from "../src/lib/artifact.js";

describe("zip intake", () => {
  test("rejects symlink-like entries from unix mode bits", () => {
    const zip = new AdmZip();
    zip.addFile("link-to-secrets", Buffer.from("target-path", "utf8"));
    const entry = zip.getEntry("link-to-secrets");
    if (!entry) throw new Error("missing test zip entry");
    entry.attr = (0o120777 << 16) >>> 0;

    const zip_b64 = zip.toBuffer().toString("base64");
    expect(() => normalizeZip({ zip_bytes_b64: zip_b64 })).toThrow(/unsupported entry type/i);
  });
});
