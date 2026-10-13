import { create } from "zustand";
import { sanitizeText } from "@/lib/sanitize";

export type NoticeTone = "info" | "success" | "warning" | "error";

export interface Notice {
  id: number;
  tone: NoticeTone;
  text: string;
  /** What the user can do about it. */
  hint?: string;
  /** Short heading such as "Permission error". */
  title?: string;
}

interface NoticeStore {
  notices: Notice[];
  push: (tone: NoticeTone, text: string, hint?: string, title?: string) => void;
  dismiss: (id: number) => void;
}

let nextId = 1;
const MAX_VISIBLE = 4;

export const useNoticeStore = create<NoticeStore>((set, get) => ({
  notices: [],
  push: (tone, rawText, rawHint, rawTitle) => {
    // Messages can embed file names or interface descriptions, which are untrusted.
    const text = sanitizeText(rawText);
    const hint = rawHint ? sanitizeText(rawHint) : undefined;
    const title = rawTitle ? sanitizeText(rawTitle) : undefined;
    const id = nextId++;
    set((s) => ({ notices: [...s.notices.filter((n) => n.text !== text), { id, tone, text, hint, title }].slice(-MAX_VISIBLE) }));
    // Errors stay until dismissed; everything else fades.
    if (tone !== "error") setTimeout(() => get().dismiss(id), tone === "warning" ? 9000 : 5000);
  },
  dismiss: (id) => set((s) => ({ notices: s.notices.filter((n) => n.id !== id) })),
}));
