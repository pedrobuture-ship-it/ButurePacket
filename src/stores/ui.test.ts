import { beforeEach, describe, expect, it } from "vitest";
import { useUiStore } from "./ui";

const s = () => useUiStore.getState();

describe("ui store: filter", () => {
  beforeEach(() => s().clearFilter());

  it("applies a valid filter and keeps its parsed form", () => {
    s().setFilterDraft("tcp && dst.port = 443");
    s().applyFilter();
    expect(s().filter).toBe("tcp && dst.port = 443");
    expect(s().filterAst).not.toBeNull();
    expect(s().filterError).toBeNull();
  });

  it("rejects an invalid filter without disturbing the active one", () => {
    s().applyFilter("dns");
    const ast = s().filterAst;
    s().setFilterDraft("latency >> 5");
    s().applyFilter();
    expect(s().filter).toBe("dns");
    expect(s().filterAst).toBe(ast);
    expect(s().filterError).toBe('Unexpected token ">>" at position 8.');
  });

  it("typing clears the previous error", () => {
    s().applyFilter("tcp &&");
    expect(s().filterError).not.toBeNull();
    s().setFilterDraft("tcp");
    expect(s().filterError).toBeNull();
  });

  it("an empty filter means 'match everything'", () => {
    s().applyFilter("dns");
    s().applyFilter("   ");
    expect(s().filter).toBe("");
    expect(s().filterAst).toBeNull();
  });

  it("clearFilter resets draft, filter and error", () => {
    s().applyFilter("dns");
    s().clearFilter();
    expect(s()).toMatchObject({ filter: "", filterDraft: "", filterAst: null, filterError: null });
  });

  it("applyFilter(text) also updates the draft (used by context menus)", () => {
    s().applyFilter("src.ip = 10.0.0.1");
    expect(s().filterDraft).toBe("src.ip = 10.0.0.1");
  });
});

describe("ui store: panes", () => {
  it("tracks overlays independently", () => {
    s().setPaletteOpen(true);
    s().setShortcutsOpen(true);
    expect(s()).toMatchObject({ paletteOpen: true, shortcutsOpen: true });
    s().setPaletteOpen(false);
    expect(s().shortcutsOpen).toBe(true);
    s().setShortcutsOpen(false);
  });
  it("changes views", () => {
    s().setView("flows");
    expect(s().view).toBe("flows");
  });
});
