"use client";

import { useTheme } from "next-themes";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { useHydrated } from "@/lib/hooks/use-hydrated";

export function ThemeSetting() {
  const { theme, setTheme } = useTheme();
  const mounted = useHydrated();

  return (
    <div className="flex items-center justify-between gap-4">
      <div className="flex flex-col gap-1">
        <Label htmlFor="theme-select">Thème</Label>
        <p className="text-sm text-muted-foreground">
          Choisissez l&apos;apparence de l&apos;interface.
        </p>
      </div>
      <Select value={mounted ? theme : undefined} onValueChange={setTheme}>
        <SelectTrigger id="theme-select" className="w-36">
          <SelectValue placeholder="…" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="dark">Sombre</SelectItem>
          <SelectItem value="light">Clair</SelectItem>
        </SelectContent>
      </Select>
    </div>
  );
}
