// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ErrorBoundary } from "./ErrorBoundary";

function Bomb({ explode }: { explode: boolean }) {
  if (explode) throw new Error("kaboom \u001b[31m");
  return <p>all good</p>;
}

describe("ErrorBoundary", () => {
  afterEach(cleanup);

  it("renders children normally", () => {
    render(
      <ErrorBoundary label="Packets">
        <Bomb explode={false} />
      </ErrorBoundary>,
    );
    expect(screen.getByText("all good")).toBeTruthy();
  });

  it("contains a crash, explains it, and sanitises the message", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    render(
      <ErrorBoundary label="Packets">
        <Bomb explode />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert").textContent).toContain("Packets ran into a problem");
    expect(screen.getByRole("alert").textContent).toContain("no capture data was lost");
    expect(screen.getByRole("alert").textContent).not.toContain("\u001b");
    spy.mockRestore();
  });

  it("recovers when asked to try again or when the reset key changes", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { rerender } = render(
      <ErrorBoundary label="Flows" resetKey="a">
        <Bomb explode />
      </ErrorBoundary>,
    );
    expect(screen.queryByText("all good")).toBeNull();
    rerender(
      <ErrorBoundary label="Flows" resetKey="b">
        <Bomb explode={false} />
      </ErrorBoundary>,
    );
    expect(screen.getByText("all good")).toBeTruthy();

    rerender(
      <ErrorBoundary label="Flows" resetKey="b">
        <Bomb explode />
      </ErrorBoundary>,
    );
    fireEvent.click(screen.getByText("Try again")); // still exploding → stays in the error state
    expect(screen.getByRole("alert")).toBeTruthy();
    spy.mockRestore();
  });
});
