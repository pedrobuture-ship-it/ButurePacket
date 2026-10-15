import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/inter";
import "@fontsource/jetbrains-mono";
import "@/styles/index.css";
import { App } from "@/app/App";
import { ErrorBoundary } from "@/components/ErrorBoundary";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ErrorBoundary label="B&M Packet">
      <App />
    </ErrorBoundary>
  </StrictMode>,
);
