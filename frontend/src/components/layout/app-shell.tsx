"use client";

import type * as React from "react";

import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
import { useCollapsedSidebar } from "@/lib/hooks/use-collapsed-sidebar";
import type { UserPublic } from "@/types/api";

export function AppShell({
  user,
  children,
}: {
  user: UserPublic;
  children: React.ReactNode;
}) {
  const [collapsed, toggleCollapsed] = useCollapsedSidebar();

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar collapsed={collapsed} onToggleCollapsed={toggleCollapsed} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar user={user} />
        <main className="flex-1 overflow-y-auto p-4 md:p-6">{children}</main>
      </div>
    </div>
  );
}
