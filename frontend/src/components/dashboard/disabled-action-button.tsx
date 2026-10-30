import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

/**
 * A button for an action the UI is "prepared" for but the backend
 * doesn't support yet (creating a target, launching a scan...). Shown
 * disabled rather than hidden, so the interface communicates the
 * feature exists and why it can't be used right now -- never silently
 * omitted, and never wired to a fake success path.
 */
export function DisabledActionButton({
  children,
  reason,
}: {
  children: ReactNode;
  reason: string;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* span wrapper: a disabled native <button> doesn't fire pointer
            events, so Radix's tooltip trigger (which listens for
            hover/focus) needs a hoverable element around it to still work. */}
        <span tabIndex={0} className="inline-flex">
          <Button disabled className="pointer-events-none">
            {children}
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>{reason}</TooltipContent>
    </Tooltip>
  );
}
