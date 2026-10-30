import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/** Standard shadcn/ui class-merging helper: clsx for conditional classes,
 * tailwind-merge to resolve conflicting Tailwind utility classes (e.g.
 * "p-2" + "p-4" -> "p-4", not both). */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
