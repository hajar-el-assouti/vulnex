import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium w-fit whitespace-nowrap",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        outline: "border-border text-foreground",
        destructive: "border-transparent bg-destructive text-destructive-foreground",
        success: "border-transparent bg-success text-success-foreground",
        // Severity scale -- see globals.css. Used by SeverityBadge, but
        // exposed here too so any table/filter chip can reuse it.
        critical: "border-transparent bg-severity-critical text-severity-critical-foreground",
        high: "border-transparent bg-severity-high text-severity-high-foreground",
        medium: "border-transparent bg-severity-medium text-severity-medium-foreground",
        low: "border-transparent bg-severity-low text-severity-low-foreground",
        info: "border-transparent bg-severity-info text-severity-info-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

function Badge({
  className,
  variant,
  ...props
}: React.ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return (
    <span data-slot="badge" className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
