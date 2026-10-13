// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { CommandPalette } from "./CommandPalette";
import { useUiStore } from "@/stores/ui";
import { useCaptureStore } from "@/stores/capture";

const open = () => act(() => useUiStore.getState().setPaletteOpen(true));

describe("CommandPalette", () => {
  beforeEach(() => {
    useUiStore.setState({ view: "overview", paletteOpen: false, filter: "", filterDraft: "" });
    useCaptureStore.getState().reset();
    useCaptureStore.getState().setInterfaces([{ name: "eth0", description: null, addresses: [], loopback: false, up: true }]);
  });
  afterEach(cleanup);

  it("renders nothing while closed", () => {
    render(<CommandPalette />);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("lists only commands that can run right now", () => {
    render(<CommandPalette />);
    open();
    const titles = screen.getAllByRole("option").map((o) => o.textContent ?? "");
    expect(titles.some((t) => t.includes("Start Capture"))).toBe(true);
    expect(titles.some((t) => t.includes("Pause Capture"))).toBe(false); // not capturing
    expect(titles.some((t) => t.includes("Stop Capture"))).toBe(false);
  });

  it("filters fuzzily and runs the highlighted command with Enter", async () => {
    render(<CommandPalette />);
    open();
    const input = screen.getByRole("combobox");
    fireEvent.change(input, { target: { value: "flows" } });
    expect(screen.getAllByRole("option")[0].textContent).toContain("Go to Flows");
    fireEvent.keyDown(input, { key: "Enter" });
    await act(async () => {
      await new Promise((r) => requestAnimationFrame(() => r(null)));
    });
    expect(useUiStore.getState().view).toBe("flows");
    expect(useUiStore.getState().paletteOpen).toBe(false);
  });

  it("moves with the arrow keys and closes with Escape", () => {
    render(<CommandPalette />);
    open();
    const input = screen.getByRole("combobox");
    expect(screen.getAllByRole("option")[0].getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(input, { key: "ArrowDown" });
    expect(screen.getAllByRole("option")[1].getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(input, { key: "ArrowUp" });
    fireEvent.keyDown(input, { key: "ArrowUp" });
    expect(screen.getAllByRole("option").at(-1)?.getAttribute("aria-selected")).toBe("true"); // wraps
    fireEvent.keyDown(window, { key: "Escape" });
    expect(useUiStore.getState().paletteOpen).toBe(false);
  });

  it("shows an empty state for nonsense queries", () => {
    render(<CommandPalette />);
    open();
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "zzzzqqq" } });
    expect(screen.getByText("No matching commands")).toBeTruthy();
  });
});
