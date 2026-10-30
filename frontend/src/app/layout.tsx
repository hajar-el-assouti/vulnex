import type { Metadata } from "next";
import { headers } from "next/headers";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";

import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";

import "./globals.css";

// Self-hosted (the `geist` package ships the font files directly)
// rather than next/font/google, which fetches from
// fonts.googleapis.com at build time -- unreachable from this
// environment's network policy, and self-hosting is one less runtime
// dependency on a third-party CDN in production anyway.

export const metadata: Metadata = {
  title: "VULNEX",
  description: "Plateforme de pentest web modulaire",
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  // Set by middleware.ts (Content-Security-Policy's script-src nonce)
  // -- next-themes' injected dark/light bootstrap script below needs
  // this exact value to run under a nonce-based CSP instead of
  // requiring 'unsafe-inline'.
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <html
      lang="fr"
      className={`${GeistSans.variable} ${GeistMono.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <body className="min-h-full bg-background text-foreground">
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem={false}
          disableTransitionOnChange
          nonce={nonce}
        >
          <TooltipProvider delayDuration={200}>{children}</TooltipProvider>
          <Toaster position="top-right" richColors closeButton />
        </ThemeProvider>
      </body>
    </html>
  );
}
