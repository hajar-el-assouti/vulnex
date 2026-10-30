import type { Metadata } from "next";

import { RegisterForm } from "@/features/auth/register-form";

export const metadata: Metadata = { title: "Créer un compte — VULNEX" };

export default function RegisterPage() {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Créer un compte</h1>
        <p className="text-sm text-muted-foreground">
          Démarrez avec la plateforme de pentest
        </p>
      </div>
      <RegisterForm />
    </div>
  );
}
