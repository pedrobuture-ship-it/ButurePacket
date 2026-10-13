import { expect, it } from "vitest";
import { cn } from "./cn";

it("joins truthy class names only", () => {
  expect(cn("a", false, null, undefined, "b")).toBe("a b");
});
