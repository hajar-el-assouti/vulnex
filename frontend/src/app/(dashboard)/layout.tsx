import type { ReactNode } from "react";
import { redirect } from "next/navigation";

import { getCurrentUser } from "@/lib/api/server";
import { AppShell } from "@/components/layout/app-shell";

/** The server-side authorization check for every private page: this
 * layout wraps dashboard/targets/scans/findings/reports/settings, and
 * runs on the server for every request to any of them (Next.js re-runs
 * a layout's Server Component on navigation within its group). A
 * missing/invalid/expired session cookie means `getCurrentUser()`
 * returns null and the user is redirected before any page body renders
 * -- there is no client-side-only gate here that a disabled-JS or
 * direct-URL request could bypass. */
export default async function DashboardLayout({ children }: { children: ReactNode }) {
  const user = await getCurrentUser();

  if (!user) {
    redirect("/login");
  }

  return <AppShell user={user}>{children}</AppShell>;
}
