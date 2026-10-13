import { copyText } from "@/lib/clipboard";
import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui";
import { sanitizeText } from "@/lib/sanitize";

interface Props {
  children: ReactNode;
  /** When this changes (e.g. the active view), a previous failure is forgotten. */
  resetKey?: string;
  label: string;
}

interface State {
  error: Error | null;
}

/** Keeps a failure inside one part of the UI: the rest of the app keeps running. */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Recoverable for the user; keep the details for bug reports.
    console.error(`[${this.props.label}]`, error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (this.state.error && prev.resetKey !== this.props.resetKey) this.setState({ error: null });
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    const details = sanitizeText(`${error.name}: ${error.message}\n${error.stack ?? ""}`);
    return (
      <div role="alert" className="flex h-full flex-col items-center justify-center gap-3 p-8 text-center">
        <AlertTriangle size={30} className="text-warning" />
        <p className="text-sm font-medium">{this.props.label} ran into a problem</p>
        <p className="max-w-md text-xs text-muted">The rest of the application is unaffected and no capture data was lost. You can try again, or switch to another view.</p>
        <p className="max-w-lg truncate font-mono text-[11px] text-muted">{sanitizeText(error.message)}</p>
        <div className="flex gap-2">
          <Button onClick={() => this.setState({ error: null })}>Try again</Button>
          <Button variant="ghost" onClick={() => copyText(details)}>
            Copy details
          </Button>
        </div>
      </div>
    );
  }
}
