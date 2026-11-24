import React from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

interface Props {
  children: React.ReactNode;
}

interface State {
  hasError: boolean;
  errorMessage: string;
}

export class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, errorMessage: "" };
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      errorMessage: error?.message || "An unexpected rendering error occurred.",
    };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    console.error("AegisPT UI ErrorBoundary caught error:", error, info.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, errorMessage: "" });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div
          role="alert"
          className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100 p-6"
        >
          <div className="w-full max-w-lg bg-slate-900 border border-red-800/60 rounded-2xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-red-500/15 border border-red-500/30">
                <AlertTriangle className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h1 className="text-base font-bold text-white">Workspace Render Error</h1>
                <p className="text-xs text-slate-400">
                  AegisPT encountered an unexpected UI error and isolated the crash.
                </p>
              </div>
            </div>

            <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-red-300 font-mono whitespace-pre-wrap break-words max-h-40 overflow-auto">
              {this.state.errorMessage}
            </pre>

            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={this.handleReset}
                className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                Try Again
              </button>
              <button
                type="button"
                onClick={() => window.location.reload()}
                className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
              >
                <RotateCcw className="w-3.5 h-3.5" /> Reload Page
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
