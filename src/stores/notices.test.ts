import { beforeEach, describe, expect, it } from "vitest";
import { useNoticeStore } from "./notices";

describe("notices", () => {
  beforeEach(() => useNoticeStore.setState({ notices: [] }));

  it("neutralises control and escape characters from untrusted text", () => {
    useNoticeStore.getState().push("error", "Could not open \u001b[31mevil.pcap\u0000");
    expect(useNoticeStore.getState().notices[0].text).toBe("Could not open ·[31mevil.pcap·");
  });

  it("de-duplicates identical messages and keeps only the latest few", () => {
    const { push } = useNoticeStore.getState();
    push("error", "same");
    push("error", "same");
    expect(useNoticeStore.getState().notices).toHaveLength(1);
    for (let i = 0; i < 10; i++) push("error", `n${i}`);
    expect(useNoticeStore.getState().notices).toHaveLength(4);
  });

  it("dismisses by id", () => {
    useNoticeStore.getState().push("error", "x");
    const id = useNoticeStore.getState().notices[0].id;
    useNoticeStore.getState().dismiss(id);
    expect(useNoticeStore.getState().notices).toEqual([]);
  });
});
