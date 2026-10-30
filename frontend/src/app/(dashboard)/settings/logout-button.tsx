"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { LogOut, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { logoutUser } from "@/features/auth/api";
import { getApiErrorMessage } from "@/lib/api/error-messages";

export function LogoutButton() {
  const router = useRouter();
  const [loading, setLoading] = React.useState(false);

  async function handleLogout() {
    setLoading(true);
    try {
      await logoutUser();
      router.push("/login");
      router.refresh();
    } catch (error) {
      toast.error(getApiErrorMessage(error));
      setLoading(false);
    }
  }

  return (
    <Button variant="destructive" onClick={handleLogout} disabled={loading}>
      {loading ? <Loader2 className="animate-spin" /> : <LogOut />}
      Déconnexion
    </Button>
  );
}
