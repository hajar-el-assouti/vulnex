"use client";

import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import {
  targetAuthorizeSchema,
  type TargetAuthorizeFormValues,
} from "@/features/targets/schemas";
import { authorizeTarget } from "@/features/targets/api";
import { getApiErrorMessage } from "@/lib/api/error-messages";
import type { TargetPublic } from "@/types/api";

interface AuthorizeTargetActionProps {
  target: TargetPublic;
  onAuthorized: (target: TargetPublic) => void;
}

/**
 * Records a claim of authorization for a target -- a separate, explicit
 * action from creating it (POST /api/v1/targets/{id}/authorize). This
 * is a pointer to proof (a ticket id, a signed scope document
 * reference), never proof itself: `is_authorized=true` alone is never
 * treated as sufficient when a scan is actually created (the backend
 * re-checks this at scan-creation time regardless of what this form
 * records -- see app/services/targets.py::ensure_target_is_authorized).
 */
export function AuthorizeTargetAction({ target, onAuthorized }: AuthorizeTargetActionProps) {
  const [open, setOpen] = React.useState(false);
  const [serverError, setServerError] = React.useState<string | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<TargetAuthorizeFormValues>({
    resolver: zodResolver(targetAuthorizeSchema),
    defaultValues: { authorization_reference: "" },
  });

  async function onSubmit(values: TargetAuthorizeFormValues) {
    setServerError(null);
    try {
      const updated = await authorizeTarget(target.id, values);
      toast.success(`Cible « ${updated.name} » autorisée.`);
      onAuthorized(updated);
      reset();
      setOpen(false);
    } catch (error) {
      setServerError(getApiErrorMessage(error));
    }
  }

  return (
    <Sheet
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) {
          setServerError(null);
          reset();
        }
      }}
    >
      <SheetTrigger asChild>
        <Button variant="outline" size="sm">
          <ShieldCheck className="size-4" />
          Autoriser
        </Button>
      </SheetTrigger>
      <SheetContent side="right" className="w-96">
        <SheetHeader>
          <SheetTitle>Autoriser « {target.name} »</SheetTitle>
        </SheetHeader>

        <p className="text-sm text-muted-foreground">
          Indiquez une référence vers la preuve d&apos;autorisation (numéro de ticket, document
          de périmètre signé...). Ceci enregistre une déclaration, pas une vérification
          automatique -- la responsabilité de l&apos;autorisation réelle reste humaine.
        </p>

        <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-4" noValidate>
          {serverError && (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{serverError}</AlertDescription>
            </Alert>
          )}

          <div className="flex flex-col gap-2">
            <Label htmlFor="authorization-reference">Référence d&apos;autorisation</Label>
            <Input
              id="authorization-reference"
              placeholder="TICKET-1234"
              aria-invalid={!!errors.authorization_reference}
              aria-describedby={
                errors.authorization_reference ? "authorization-reference-error" : undefined
              }
              {...register("authorization_reference")}
            />
            {errors.authorization_reference && (
              <p id="authorization-reference-error" className="text-sm text-destructive">
                {errors.authorization_reference.message}
              </p>
            )}
          </div>

          <Button type="submit" disabled={isSubmitting} className="mt-2">
            {isSubmitting && <Loader2 className="animate-spin" aria-hidden="true" />}
            Confirmer l&apos;autorisation
          </Button>
        </form>
      </SheetContent>
    </Sheet>
  );
}
