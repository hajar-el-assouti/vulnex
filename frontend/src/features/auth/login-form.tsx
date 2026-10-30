"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Eye, EyeOff, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { loginSchema, type LoginFormValues } from "@/features/auth/schemas";
import { loginUser } from "@/features/auth/api";
import { getApiErrorMessage } from "@/lib/api/error-messages";

export function LoginForm({ defaultEmail }: { defaultEmail?: string }) {
  const router = useRouter();
  const [serverError, setServerError] = React.useState<string | null>(null);
  const [showPassword, setShowPassword] = React.useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: defaultEmail ?? "", password: "" },
  });

  async function onSubmit(values: LoginFormValues) {
    setServerError(null);
    try {
      await loginUser(values);
      router.push("/dashboard");
      router.refresh(); // re-run Server Components now that the session cookie exists
    } catch (error) {
      setServerError(getApiErrorMessage(error));
    }
  }

  return (
    // `method="post"` is a fail-safe, not the real submission path: every
    // actual submit goes through handleSubmit(onSubmit) below, which
    // calls preventDefault() and POSTs JSON via fetch. But if JavaScript
    // never hydrates this form for any reason (a slow/blocked network, a
    // script error, JS disabled), the browser falls back to its native
    // <form> submission -- and a <form> with no explicit method defaults
    // to GET, which would put the password straight into the URL (and
    // from there into browser history and server access logs). Setting
    // method="post" here means that fallback, if it ever happens, submits
    // safely instead: it still won't log the user in (there is no
    // server-side handler at this path expecting a form POST), but it
    // never exposes credentials in a URL. See
    // login-form.test.tsx ("falls back to a safe POST").
    <form
      onSubmit={handleSubmit(onSubmit)}
      method="post"
      className="flex flex-col gap-4"
      noValidate
    >
      {serverError && (
        <Alert variant="destructive" role="alert">
          <AlertDescription>{serverError}</AlertDescription>
        </Alert>
      )}

      <div className="flex flex-col gap-2">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          autoComplete="email"
          aria-invalid={!!errors.email}
          aria-describedby={errors.email ? "email-error" : undefined}
          {...register("email")}
        />
        {errors.email && (
          <p id="email-error" className="text-sm text-destructive">
            {errors.email.message}
          </p>
        )}
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="password">Mot de passe</Label>
        <div className="relative">
          <Input
            id="password"
            type={showPassword ? "text" : "password"}
            autoComplete="current-password"
            aria-invalid={!!errors.password}
            aria-describedby={errors.password ? "password-error" : undefined}
            className="pr-10"
            {...register("password")}
          />
          <button
            type="button"
            onClick={() => setShowPassword((v) => !v)}
            className="absolute inset-y-0 right-0 flex items-center px-3 text-muted-foreground hover:text-foreground"
            aria-label={showPassword ? "Masquer le mot de passe" : "Afficher le mot de passe"}
            aria-pressed={showPassword}
          >
            {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
          </button>
        </div>
        {errors.password && (
          <p id="password-error" className="text-sm text-destructive">
            {errors.password.message}
          </p>
        )}
      </div>

      <Button type="submit" disabled={isSubmitting} className="mt-2">
        {isSubmitting && <Loader2 className="animate-spin" aria-hidden="true" />}
        Se connecter
      </Button>

      <p className="text-center text-sm text-muted-foreground">
        Pas encore de compte ?{" "}
        <Link href="/register" className="font-medium text-primary hover:underline">
          Créer un compte
        </Link>
      </p>
    </form>
  );
}
