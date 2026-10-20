/** `s` shortened to its first and last `n` characters (after any 0x), as the page shows ids. */
export function short(s: string | null | undefined, n = 6): string {
  if (!s) return '';
  return s.length > 2 * n + 1 ? `${s.slice(0, n + (s.startsWith('0x') ? 2 : 0))}…${s.slice(-n)}` : s;
}

/** An error's message, or the value itself as text. */
export function message(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e && typeof e.message === 'string' && e.message) return e.message;
  return String(e);
}

export const plural = (n: number, word: string) => `${n.toLocaleString('en')} ${word}${n === 1 ? '' : 's'}`;
