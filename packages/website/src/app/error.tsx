"use client";

import { useEffect } from "react";

export default function RootError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[root-error]", error);
  }, [error]);

  return (
    <html lang="en">
      <body style={{ background: "#1A1614", color: "#F5F1E8", fontFamily: "system-ui, sans-serif" }}>
        <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "24px" }}>
          <div style={{ maxWidth: "400px", textAlign: "center" }}>
            <h1 style={{ fontSize: "24px", fontWeight: "bold", marginBottom: "12px" }}>
              Something went wrong
            </h1>
            <p style={{ color: "#A09890", fontSize: "14px", marginBottom: "24px" }}>
              An unexpected error occurred. Please try again.
            </p>
            <button
              onClick={reset}
              style={{
                background: "#8B9A8E",
                color: "#1A1614",
                border: "none",
                borderRadius: "999px",
                padding: "12px 24px",
                fontWeight: 600,
                fontSize: "14px",
                cursor: "pointer",
              }}
            >
              Try again
            </button>
          </div>
        </div>
      </body>
    </html>
  );
}
