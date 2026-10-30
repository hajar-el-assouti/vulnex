"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck, PanelLeftClose, PanelLeftOpen } from "lucide-react";

import { SidebarNav } from "@/components/layout/sidebar-nav";
import { Button } from "@/components/ui/button";
import { NAV_ITEMS } from "@/lib/nav-config";
import { cn } from "@/lib/utils";

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

/** Desktop sidebar only (hidden below md); the mobile equivalent is the
 * Sheet rendered from the topbar's hamburger trigger (see
 * MobileNavTrigger), reusing the same SidebarNav. */
export function Sidebar({ collapsed, onToggleCollapsed }: SidebarProps) {
  return (
    <aside
      className={cn(
        "hidden shrink-0 flex-col border-r border-border bg-surface transition-[width] duration-200 md:flex",
        collapsed ? "w-16" : "w-60",
      )}
    >
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <ShieldCheck className="size-5 shrink-0 text-primary" aria-hidden="true" />
        {!collapsed && <span className="truncate text-sm font-semibold">VULNEX</span>}
      </div>

      <div className="flex-1 overflow-y-auto py-3">
        {collapsed ? <SidebarIconsOnly /> : <SidebarNav />}
      </div>

      <div className="border-t border-border p-2">
        <Button
          variant="ghost"
          size="icon"
          className="w-full"
          onClick={onToggleCollapsed}
          aria-label={collapsed ? "Déployer la barre latérale" : "Réduire la barre latérale"}
        >
          {collapsed ? (
            <PanelLeftOpen className="size-4" />
          ) : (
            <PanelLeftClose className="size-4" />
          )}
        </Button>
      </div>
    </aside>
  );
}

/** Icon-only nav shown when the sidebar is collapsed -- keeps every
 * link reachable (and labelled for screen readers) rather than hiding
 * navigation behind the collapse. */
function SidebarIconsOnly() {
  const pathname = usePathname();
  return (
    <nav aria-label="Navigation principale (réduite)" className="flex flex-col gap-1 px-2">
      {NAV_ITEMS.map((item) => {
        const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`);
        const Icon = item.icon;
        return (
          <Link
            key={item.href}
            href={item.href}
            title={item.label}
            aria-label={item.label}
            aria-current={isActive ? "page" : undefined}
            className={cn(
              "flex items-center justify-center rounded-md p-2.5 transition-colors",
              isActive
                ? "bg-primary/10 text-primary"
                : "text-muted-foreground hover:bg-surface-hover hover:text-foreground",
            )}
          >
            <Icon className="size-4" aria-hidden="true" />
          </Link>
        );
      })}
    </nav>
  );
}
