"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight } from "lucide-react";

import { PAGE_TITLES } from "@/lib/nav-config";

function titleCase(segment: string): string {
  return segment
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

export function Breadcrumbs() {
  const pathname = usePathname();
  const segments = pathname.split("/").filter(Boolean);

  const crumbs = segments.map((segment, index) => {
    const href = `/${segments.slice(0, index + 1).join("/")}`;
    const label = PAGE_TITLES[href] ?? titleCase(segment);
    return { href, label, isLast: index === segments.length - 1 };
  });

  if (crumbs.length === 0) return null;

  return (
    <nav aria-label="Fil d'Ariane" className="hidden sm:block">
      <ol className="flex items-center gap-1.5 text-sm text-muted-foreground">
        {crumbs.map((crumb) => (
          <li key={crumb.href} className="flex items-center gap-1.5">
            {crumb.isLast ? (
              <span aria-current="page" className="font-medium text-foreground">
                {crumb.label}
              </span>
            ) : (
              <>
                <Link href={crumb.href} className="hover:text-foreground">
                  {crumb.label}
                </Link>
                <ChevronRight className="size-3.5" aria-hidden="true" />
              </>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
