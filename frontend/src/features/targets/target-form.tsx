"use client";

import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2, Plus } from "lucide-react";
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
import { targetCreateSchema, type TargetCreateFormValues } from "@/features/targets/schemas";
import { createTarget } from "@/features/targets/api";
import { getApiErrorMessage } from "@/lib/api/error-messages";
import type { TargetPublic } from "@/types/api";

interface TargetFormProps {
  onCreated: (target: TargetPublic) => void;
}

/** "Nouvelle cible" button + Sheet form, wired to the real POST
 * /api/v1/targets endpoint (app/api/v1/endpoints/targets.py). A created
 * target starts unauthorized (is_authorized=false) -- there is no path
 * from this form to an authorized target; see AuthorizeTargetAction for
 * the separate, explicit action that records a claim of authorization. */
export function TargetForm({ onCreated }: TargetFormProps) {
  const [open, setOpen] = React.useState(false);
  const [serverError, setServerError] = React.useState<string | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<TargetCreateFormValues>({
    resolver: zodResolver(targetCreateSchema),
    defaultValues: { name: "", base_url: "", description: "" },
  });

  async function onSubmit(values: TargetCreateFormValues) {
    setServerError(null);
    try {
      const target = await createTarget({
        name: values.name,
        base_url: values.base_url,
        description: values.description ? values.description : null,
      });
      toast.success(`Cible « ${target.name} » créée.`);
      onCreated(target);
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
        <Button>
          <Plus className="size-4" />
          Nouvelle cible
        </Button>
      </SheetTrigger>
      <SheetContent side="right" className="w-96">
        <SheetHeader>
          <SheetTitle>Nouvelle cible</SheetTitle>
        </SheetHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-4" noValidate>
          {serverError && (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{serverError}</AlertDescription>
            </Alert>
          )}

          <div className="flex flex-col gap-2">
            <Label htmlFor="target-name">Nom</Label>
            <Input
              id="target-name"
              aria-invalid={!!errors.name}
              aria-describedby={errors.name ? "target-name-error" : undefined}
              {...register("name")}
            />
            {errors.name && (
              <p id="target-name-error" className="text-sm text-destructive">
                {errors.name.message}
              </p>
            )}
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="target-base-url">URL de base</Label>
            <Input
              id="target-base-url"
              placeholder="https://exemple.lab.local"
              aria-invalid={!!errors.base_url}
              aria-describedby={errors.base_url ? "target-base-url-error" : undefined}
              {...register("base_url")}
            />
            {errors.base_url && (
              <p id="target-base-url-error" className="text-sm text-destructive">
                {errors.base_url.message}
              </p>
            )}
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="target-description">Description (optionnel)</Label>
            <Input id="target-description" {...register("description")} />
          </div>

          <Button type="submit" disabled={isSubmitting} className="mt-2">
            {isSubmitting && <Loader2 className="animate-spin" aria-hidden="true" />}
            Créer la cible
          </Button>
        </form>
      </SheetContent>
    </Sheet>
  );
}
