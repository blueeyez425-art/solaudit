import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SolAudit — Solana/Anchor Security Scanner",
  description:
    "Scan your Anchor/Solana Rust programs for common vulnerability patterns — missing signer checks, arbitrary CPIs, integer overflow, and more. Paste a GitHub repo URL or upload a .rs file, no install required.",
  metadataBase: new URL("https://solaudit.dev"),
  openGraph: {
    title: "SolAudit — Solana/Anchor Security Scanner",
    description:
      "Free, instant static analysis for Anchor/Solana programs. Paste a repo URL or upload a .rs file.",
    type: "website",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100 antialiased">{children}</body>
    </html>
  );
}
