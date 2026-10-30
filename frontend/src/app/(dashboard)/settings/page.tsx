import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { getCurrentUser } from "@/lib/api/server";
import { ThemeSetting } from "@/app/(dashboard)/settings/theme-setting";
import { LogoutButton } from "@/app/(dashboard)/settings/logout-button";

export const metadata: Metadata = { title: "Settings — VULNEX" };

/**
 * Account info comes from GET /api/v1/auth/me (getCurrentUser(),
 * already resolved by the layout and reused through React's cache()).
 * There is no profile edit form because the backend has no endpoint to
 * change email, name or password.
 */
export default async function SettingsPage() {
  const user = await getCurrentUser();
  if (!user) {
    redirect("/login");
  }

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base text-foreground">Compte</CardTitle>
          <CardDescription>Informations liées à votre compte connecté.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Field label="Email" value={user.email} mono />
          <Field label="Nom complet" value={user.full_name || "—"} />
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Rôle</span>
            <Badge variant="outline" className="capitalize">
              {user.role}
            </Badge>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Statut</span>
            <Badge variant={user.is_active ? "success" : "destructive"}>
              {user.is_active ? "Actif" : "Inactif"}
            </Badge>
          </div>
          <Field
            label="Membre depuis"
            value={new Date(user.created_at).toLocaleDateString("fr-FR", {
              year: "numeric",
              month: "long",
              day: "numeric",
            })}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base text-foreground">Préférences</CardTitle>
        </CardHeader>
        <CardContent>
          <ThemeSetting />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base text-foreground">Session</CardTitle>
          <CardDescription>Met fin à votre session actuelle sur cet appareil.</CardDescription>
        </CardHeader>
        <CardContent>
          <LogoutButton />
        </CardContent>
      </Card>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <div className="flex items-center justify-between gap-4">
        <span className="text-sm text-muted-foreground">{label}</span>
        <span className={mono ? "font-mono text-sm" : "text-sm"}>{value}</span>
      </div>
      <Separator />
    </>
  );
}
