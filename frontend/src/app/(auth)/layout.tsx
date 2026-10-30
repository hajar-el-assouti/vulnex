import type { ReactNode } from "react";
import { redirect } from "next/navigation";
import { ShieldCheck } from "lucide-react";

import { getCurrentUser } from "@/lib/api/server";
import { ThemeToggle } from "@/components/layout/theme-toggle";

export default async function AuthLayout({ children }: { children: ReactNode }) {
  // Already authenticated? Login/register have nothing to offer them --
  // send them straight to the app instead of showing a login form.
  const user = await getCurrentUser();
  if (user) {
    redirect("/dashboard");
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="flex items-center justify-between p-4">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <ShieldCheck className="size-5 text-primary" aria-hidden="true" />
          VULNEX
        </div>
        <ThemeToggle />
      </header>
      <main className="flex flex-1 items-center justify-center p-4">
        <div className="w-full max-w-sm">{children}</div>
      </main>
    </div>
  );
}
