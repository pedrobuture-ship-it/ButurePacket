/**
 * Captured data is untrusted. React escapes HTML, but terminal escapes and other
 * control characters can still confuse copy/paste and layout, so neutralise them.
 */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g;

export function sanitizeText(text: string): string {
  return text.replace(CONTROL, "·");
}

/** Printable ASCII for the hex dump gutter; everything else becomes '.'. */
export function asciiChar(byte: number): string {
  return byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".";
}
