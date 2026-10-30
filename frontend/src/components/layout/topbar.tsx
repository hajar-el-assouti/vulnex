"use client";

import { usePathname } from "next/navigation";

import { MobileNav } from "@/components/layout/mobile-nav";
import { Breadcrumbs } from "@/components/layout/breadcrumbs";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { UserMenu } from "@/components/layout/user-menu";
import { PAGE_TITLES } from "@/lib/nav-config";
import type { UserPublic } from "@/types/api";

export function Topbar({ user }: { user: UserPublic }) {
  const pathname = usePathname();
  const rootSegment = `/${pathname.split("/").filter(Boolean)[0] ?? ""}`;
  const title = PAGE_TITLES[rootSegment] ?? "VULNEX";

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border bg-surface px-4">
      <MobileNav />
      <div className="flex flex-1 items-center gap-3 min-w-0">
        <h1 className="truncate text-base font-semibold">{title}</h1>
        <Breadcrumbs />
      </div>
      <ThemeToggle />
      <UserMenu user={user} />
    </header>
  );
}
