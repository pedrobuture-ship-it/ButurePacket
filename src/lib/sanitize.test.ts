import { describe, expect, it } from "vitest";
import { asciiChar, sanitizeText } from "./sanitize";

describe("sanitize", () => {
  it("neutralises ANSI escapes and control characters", () => {
    expect(sanitizeText("\u001b[31mred\u001b[0m\u0000")).toBe("·[31mred·[0m·");
  });
  it("neutralises bidi overrides", () => {
    expect(sanitizeText("a‮b")).toBe("a·b");
  });
  it("leaves normal text alone", () => {
    expect(sanitizeText("api.github.com → 443")).toBe("api.github.com → 443");
  });
  it("maps non-printable bytes to dots", () => {
    expect(asciiChar(0x41)).toBe("A");
    expect(asciiChar(0x0a)).toBe(".");
    expect(asciiChar(0x7f)).toBe(".");
    expect(asciiChar(0xff)).toBe(".");
  });
});
