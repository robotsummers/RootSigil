export function lineRangeFromOffsets(text: string, start: number, end: number): { line_start: number; line_end: number } {
  const safeStart = clamp(start, 0, text.length);
  const safeEnd = clamp(end, safeStart, text.length);

  const prefix = text.slice(0, safeStart);
  const span = text.slice(safeStart, safeEnd);
  const lineStart = countLines(prefix) + 1;
  const lineEnd = lineStart + countLines(span);

  return { line_start: lineStart, line_end: lineEnd };
}

function countLines(s: string): number {
  let lines = 0;
  for (let i = 0; i < s.length; i += 1) {
    if (s.charCodeAt(i) === 10) lines += 1;
  }
  return lines;
}

function clamp(n: number, min: number, max: number): number {
  if (n < min) return min;
  if (n > max) return max;
  return n;
}
