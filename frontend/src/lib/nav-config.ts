import type { LucideIcon } from "lucide-react";
import {
  LayoutDashboard,
  Target,
  ScanSearch,
  ShieldAlert,
  FileText,
  Settings,
} from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

export const NAV_ITEMS: NavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/targets", label: "Targets", icon: Target },
  { href: "/scans", label: "Scans", icon: ScanSearch },
  { href: "/findings", label: "Findings", icon: ShieldAlert },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings },
];

/** Page title shown in the topbar, by route prefix. Falls back to the
 * matching NAV_ITEMS label when a path isn't listed here (e.g. a detail
 * page keeps its section's title). */
export const PAGE_TITLES: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/targets": "Targets",
  "/scans": "Scans",
  "/findings": "Findings",
  "/reports": "Reports",
  "/settings": "Settings",
};
