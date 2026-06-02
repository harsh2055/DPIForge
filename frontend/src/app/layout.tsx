import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DPIForge — Deep Packet Inspector",
  description:
    "Real-time network traffic analyzer with TLS SNI extraction, application classification, and live blocking rules. Built with Python/FastAPI + Next.js.",
  keywords: ["packet analyzer", "DPI", "network monitor", "TLS SNI", "traffic analysis"],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="scanlines grid-bg">{children}</body>
    </html>
  );
}
