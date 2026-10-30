import type { Metadata } from "next";
import { CheckCircle2 } from "lucide-react";

import { LoginForm } from "@/features/auth/login-form";
import { Alert, AlertDescription } from "@/components/ui/alert";

export const metadata: Metadata = { title: "Connexion — VULNEX" };

interface LoginPageProps {
  searchParams: Promise<{ registered?: string; email?: string }>;
}

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const params = await searchParams;
  const justRegistered = params.registered === "1";

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Connexion</h1>
        <p className="text-sm text-muted-foreground">Accédez à votre espace pentest</p>
      </div>
      {justRegistered && (
        <Alert className="border-success/40 bg-success/10 text-success">
          <CheckCircle2 className="size-4" aria-hidden="true" />
          <AlertDescription>Compte créé. Vous pouvez maintenant vous connecter.</AlertDescription>
        </Alert>
      )}
      <LoginForm defaultEmail={params.email} />
    </div>
  );
}
