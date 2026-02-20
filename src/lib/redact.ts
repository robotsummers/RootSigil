const SECRET_PATTERNS: RegExp[] = [
  /0x[a-fA-F0-9]{64}/g, // 32-byte hex private key
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /AKIA[0-9A-Z]{16}/g, // AWS access key id (best-effort)
  /xox[bp]-[A-Za-z0-9-]+/g, // Slack token prefixes
  /ghp_[A-Za-z0-9]{20,}/g, // GitHub PAT prefix
  /sk-[A-Za-z0-9]{16,}/g, // Common API key prefix
  /(api_key|apikey|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{16,}/gi
];

export function redactText(input: string): string {
  let out = input;
  for (const re of SECRET_PATTERNS) {
    out = out.replace(re, "[REDACTED]");
  }
  return out;
}
