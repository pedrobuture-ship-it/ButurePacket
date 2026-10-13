// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { Notices } from "./Overlays";
import { useNoticeStore } from "@/stores/notices";

describe("Notices", () => {
  beforeEach(() => useNoticeStore.setState({ notices: [] }));
  afterEach(cleanup);

  it("renders nothing without notices", () => {
    const { container } = render(<Notices />);
    expect(container.textContent).toBe("");
  });

  it("shows heading, message and hint, with untrusted text neutralised", () => {
    render(<Notices />);
    act(() => useNoticeStore.getState().push("error", "Cannot read \u001b[31mevil.pcap", "Check the file.", "File error"));
    expect(screen.getByRole("alert").textContent).toContain("File error");
    expect(screen.getByRole("alert").textContent).toContain("Cannot read ·[31mevil.pcap");
    expect(screen.getByRole("alert").textContent).toContain("Check the file.");
  });

  it("dismisses on click", () => {
    render(<Notices />);
    act(() => useNoticeStore.getState().push("error", "Something failed"));
    fireEvent.click(screen.getByLabelText("Dismiss"));
    expect(screen.queryByText("Something failed")).toBeNull();
  });
});
