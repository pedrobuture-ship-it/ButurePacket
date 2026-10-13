import { describe, expect, it } from "vitest";
import { isTypingTarget, matchShortcut, shortcutKeys, type KeyLike } from "./shortcuts";

const ev = (key: string, mods: Partial<KeyLike> = {}): KeyLike => ({ key, ctrlKey: false, metaKey: false, shiftKey: false, altKey: false, ...mods });

describe("matchShortcut", () => {
  it("matches modifier combinations exactly", () => {
    expect(matchShortcut(ev("k", { ctrlKey: true }), "Ctrl+K")).toBe(true);
    expect(matchShortcut(ev("K", { ctrlKey: true }), "Ctrl+K")).toBe(true);
    expect(matchShortcut(ev("k", { ctrlKey: true, shiftKey: true }), "Ctrl+K")).toBe(false);
    expect(matchShortcut(ev("k"), "Ctrl+K")).toBe(false);
    expect(matchShortcut(ev("k", { ctrlKey: true }), "K")).toBe(false);
    expect(matchShortcut(ev("p", { ctrlKey: true, shiftKey: true }), "Ctrl+Shift+P")).toBe(true);
  });
  it("ignores Shift for symbol keys such as ?", () => {
    expect(matchShortcut(ev("?", { shiftKey: true }), "?")).toBe(true);
    expect(matchShortcut(ev("?"), "?")).toBe(true);
    expect(matchShortcut(ev("?", { ctrlKey: true }), "?")).toBe(false);
  });
  it("treats Cmd as Ctrl", () => expect(matchShortcut(ev("o", { metaKey: true }), "Ctrl+O")).toBe(true));
  it("matches named keys", () => {
    expect(matchShortcut(ev(" "), "Space")).toBe(true);
    expect(matchShortcut(ev("Escape"), "Esc")).toBe(true);
    expect(matchShortcut(ev("Enter"), "Enter")).toBe(true);
    expect(matchShortcut(ev("j"), "J")).toBe(true);
    expect(matchShortcut(ev(" ", { ctrlKey: true }), "Space")).toBe(false);
  });
});

describe("shortcutKeys", () => {
  it("formats for display", () => {
    expect(shortcutKeys("Ctrl+K")).toEqual(["Ctrl", "K"]);
    expect(shortcutKeys("Space")).toEqual(["Space"]);
    expect(shortcutKeys("Ctrl+Shift+p")).toEqual(["Ctrl", "Shift", "P"]);
  });
});

describe("isTypingTarget", () => {
  const el = (tagName: string, role: string | null = null, editable = false) => ({ tagName, isContentEditable: editable, getAttribute: () => role }) as unknown as EventTarget;
  it("detects inputs and controls", () => {
    expect(isTypingTarget(el("INPUT"))).toBe(true);
    expect(isTypingTarget(el("TEXTAREA"))).toBe(true);
    expect(isTypingTarget(el("DIV", null, true))).toBe(true);
    expect(isTypingTarget(el("BUTTON"))).toBe(true);
    expect(isTypingTarget(el("DIV", "menuitem"))).toBe(true);
  });
  it("lets plain containers through", () => {
    expect(isTypingTarget(el("DIV"))).toBe(false);
    expect(isTypingTarget(null)).toBe(false);
  });
});
