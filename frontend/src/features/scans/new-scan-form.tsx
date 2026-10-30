"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Controller, useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2, Play } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { DisabledActionButton } from "@/components/dashboard/disabled-action-button";
import { MODULE_DESCRIPTIONS, MODULE_LABELS } from "@/features/scans/module-labels";
import { scanCreateSchema, type ScanCreateFormValues } from "@/features/scans/schemas";
import { createScan, listScanModules } from "@/features/scans/api";
import { listScanProfiles } from "@/features/scan-profiles/api";
import { getApiErrorMessage } from "@/lib/api/error-messages";
import type { ScanModulePublic, ScanProfilePublic, TargetPublic } from "@/types/api";

interface NewScanFormProps {
  authorizedTargets: TargetPublic[];
  defaultTargetId?: string;
}

/**
 * New scan form.
 *
 * The user picks which enabled modules to run. The list comes from
 * GET /scan-modules, never hardcoded, so new modules show up
 * automatically. All enabled modules are checked by default, which
 * matches the backend's fallback when no modules are sent
 * (services/scans.py::create_scan). The backend re-validates every slug
 * (services/scan_modules.py::get_enabled_modules_by_slugs); the
 * validation here is only for a better UX.
 *
 * Recon modules produce observations and, where noted, hypotheses,
 * never confirmed vulnerability findings.
 */
export function NewScanForm({ authorizedTargets, defaultTargetId }: NewScanFormProps) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [serverError, setServerError] = React.useState<string | null>(null);
  const [availableModules, setAvailableModules] = React.useState<ScanModulePublic[] | null>(null);
  const [modulesError, setModulesError] = React.useState<string | null>(null);
  const [profiles, setProfiles] = React.useState<ScanProfilePublic[]>([]);
  const [selectedProfileId, setSelectedProfileId] = React.useState<string>("none");

  const {
    control,
    handleSubmit,
    reset,
    setValue,
    formState: { errors, isSubmitting },
  } = useForm<ScanCreateFormValues>({
    resolver: zodResolver(scanCreateSchema),
    defaultValues: { target_id: defaultTargetId ?? "", modules: [], active_testing_confirmed: false },
  });

  // Watched (not read once) so the confirmation checkbox appears and
  // disappears as the user checks or unchecks an active module. The
  // list in schemas.ts is only a UI helper; the backend check is
  // generic (requires_active_confirmation on each module).
  const ACTIVE_MODULE_SLUGS = ["active_web_testing", "discovery_fuzzing"];
  const selectedModules = useWatch({ control, name: "modules" }) ?? [];
  const activeWebTestingSelected = selectedModules.some((slug) =>
    ACTIVE_MODULE_SLUGS.includes(slug),
  );

  React.useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    listScanModules(controller.signal)
      .then((response) => {
        setAvailableModules(response.items);
        // Pre-select every enabled module, mirroring the backend's own
        // "no modules specified" default (services/scans.py::create_scan).
        setValue("modules", response.items.map((module) => module.slug));
      })
      .catch((err) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setModulesError(getApiErrorMessage(err));
      });
    listScanProfiles(controller.signal)
      .then((response) => setProfiles(response.items))
      .catch((err) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        // Non-fatal: the profile picker is a convenience -- the module
        // checkboxes above still work without it.
      });
    return () => controller.abort();
  }, [open, setValue]);

  // A profile only pre-fills which modules are checked; it is never an
  // authorization shortcut. It never pre-ticks active_testing_confirmed,
  // even when the profile's active_testing_confirmed_default is true:
  // the user must confirm explicitly each time. A profile can reference
  // a module that is currently disabled (profiles only check that the
  // slug exists); those slugs are ignored here since there is no
  // checkbox for them.
  function applyProfile(profileId: string) {
    setSelectedProfileId(profileId);
    if (profileId === "none" || !availableModules) return;
    const profile = profiles.find((p) => p.id === profileId);
    if (!profile) return;
    const availableSlugs = new Set(availableModules.map((m) => m.slug));
    const applicable = profile.module_slugs.filter((slug) => availableSlugs.has(slug));
    setValue("modules", applicable);
    if (!applicable.some((slug) => ACTIVE_MODULE_SLUGS.includes(slug))) {
      setValue("active_testing_confirmed", false);
    }
  }

  async function onSubmit(values: ScanCreateFormValues) {
    setServerError(null);
    try {
      const scan = await createScan({
        target_id: values.target_id,
        modules: values.modules,
        active_testing_confirmed: values.active_testing_confirmed,
      });
      toast.success("Scan lancé.");
      reset();
      setOpen(false);
      router.push(`/scans/${scan.id}`);
    } catch (error) {
      setServerError(getApiErrorMessage(error));
    }
  }

  if (authorizedTargets.length === 0) {
    return (
      <DisabledActionButton reason="Autorisez au moins une cible avant de pouvoir lancer un scan.">
        <Play className="size-4" />
        Lancer un scan
      </DisabledActionButton>
    );
  }

  return (
    <Sheet
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) {
          setServerError(null);
          setSelectedProfileId("none");
          reset();
        }
      }}
    >
      <SheetTrigger asChild>
        <Button>
          <Play className="size-4" />
          Lancer un scan
        </Button>
      </SheetTrigger>
      {/*
       * The panel content (module list and active testing notice) can be
       * taller than the screen. SheetContent already takes the full window
       * height, so here we cap it at `90dvh`, add `overflow-hidden`, and let
       * only the body scroll (`flex-1 min-h-0`) between a fixed header and
       * footer. `min-h-0` is needed, otherwise the flex child won't shrink
       * and the scrollbar never appears. Browsers without `dvh` ignore the
       * value and keep SheetContent's `h-full`.
       */}
      <SheetContent
        side="right"
        className="flex max-h-[90dvh] w-96 flex-col overflow-hidden"
      >
        <SheetHeader className="shrink-0">
          <SheetTitle>Lancer un scan</SheetTitle>
        </SheetHeader>

        <form
          onSubmit={handleSubmit(onSubmit)}
          className="flex flex-1 min-h-0 flex-col gap-4"
          noValidate
        >
          {/*
           * Scrollable body: every field, the module checklist and the
           * active-testing disclaimer live here so the scrollbar lets
           * the user reach all of them, however long the list gets.
           * Checkbox state lives in react-hook-form's `control` (via
           * `useWatch`/`Controller` above), not in this DOM subtree, so
           * nothing is remounted and nothing is lost while scrolling.
           */}
          <div className="flex flex-1 min-h-0 flex-col gap-4 overflow-y-auto pr-1">
            <Alert>
              <AlertDescription>
                Le moteur Recon (reconnaissance web passive : HTTP, en-têtes, cookies,
                technologies, métadonnées, DNS, sécurité email, infrastructure IP/ASN, RDAP, TLS,
                ressources externes et découverte d&apos;API) produit des observations et, le cas
                échéant, des hypothèses explicitement marquées comme telles -- jamais des
                vulnérabilités confirmées. Choisissez ci-dessous les modules à exécuter pour ce
                scan.
              </AlertDescription>
            </Alert>

            {serverError && (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{serverError}</AlertDescription>
              </Alert>
            )}

            <div className="flex flex-col gap-2">
              <Label htmlFor="scan-target">Cible autorisée</Label>
              <Controller
                control={control}
                name="target_id"
                render={({ field }) => (
                  <Select value={field.value} onValueChange={field.onChange}>
                    <SelectTrigger id="scan-target" aria-invalid={!!errors.target_id}>
                      <SelectValue placeholder="Choisissez une cible" />
                    </SelectTrigger>
                    <SelectContent>
                      {authorizedTargets.map((target) => (
                        <SelectItem key={target.id} value={target.id}>
                          {target.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />
              {errors.target_id && (
                <p className="text-sm text-destructive">{errors.target_id.message}</p>
              )}
            </div>

          {profiles.length > 0 && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="scan-profile">Profil (optionnel)</Label>
              <Select value={selectedProfileId} onValueChange={applyProfile}>
                <SelectTrigger id="scan-profile">
                  <SelectValue placeholder="Aucun profil (sélection manuelle)" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">Aucun profil (sélection manuelle)</SelectItem>
                  {profiles.map((profile) => (
                    <SelectItem key={profile.id} value={profile.id}>
                      {profile.name}
                      {profile.is_builtin ? "" : " (personnalisé)"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Un profil ne pré-sélectionne que les modules ci-dessous -- l&apos;autorisation des
                tests actifs reste toujours à confirmer explicitement.
              </p>
            </div>
          )}

          <div className="flex flex-col gap-2">
            <Label>Modules à exécuter</Label>
            {modulesError && (
              <p className="text-sm text-destructive" role="alert">
                {modulesError}
              </p>
            )}
            {!availableModules && !modulesError && (
              <p className="text-sm text-muted-foreground">Chargement des modules...</p>
            )}
            {availableModules && (
              <Controller
                control={control}
                name="modules"
                render={({ field }) => (
                  <div className="flex flex-col gap-2">
                    {availableModules.map((module) => {
                      const checked = field.value?.includes(module.slug) ?? false;
                      return (
                        <label
                          key={module.slug}
                          className="flex items-start gap-2 rounded-md border p-2 text-sm"
                        >
                          <input
                            type="checkbox"
                            className="mt-0.5 size-4"
                            checked={checked}
                            onChange={(event) => {
                              const next = event.target.checked
                                ? [...(field.value ?? []), module.slug]
                                : (field.value ?? []).filter((slug) => slug !== module.slug);
                              field.onChange(next);
                              // Unchecking an active module resets the confirmation,
                              // but only once no active module is selected anymore
                              // (unchecking discovery_fuzzing while active_web_testing
                              // is still checked keeps the confirmation).
                              if (
                                ACTIVE_MODULE_SLUGS.includes(module.slug) &&
                                !event.target.checked &&
                                !next.some((slug) => ACTIVE_MODULE_SLUGS.includes(slug))
                              ) {
                                setValue("active_testing_confirmed", false);
                              }
                            }}
                          />
                          <span className="flex flex-col">
                            <span className="font-medium">{MODULE_LABELS[module.slug] ?? module.name}</span>
                            <span className="text-xs text-muted-foreground">
                              {MODULE_DESCRIPTIONS[module.slug] ?? module.description}
                            </span>
                          </span>
                        </label>
                      );
                    })}
                  </div>
                )}
              />
            )}
            {errors.modules && (
              <p className="text-sm text-destructive">{errors.modules.message}</p>
            )}
          </div>

          {activeWebTestingSelected && (
            <Alert variant="destructive">
              <AlertDescription className="flex flex-col gap-2">
                <span>
                  {selectedModules.includes("active_web_testing") && (
                    <>
                      Le module <strong>Tests actifs de vulnérabilités</strong> envoie de vraies
                      requêtes de test (marqueurs XSS inoffensifs, sondes SQLi non destructives,
                      paramètres HTTP inattendus) à la cible.{" "}
                    </>
                  )}
                  {selectedModules.includes("discovery_fuzzing") && (
                    <>
                      Le module <strong>Découverte de chemins et fichiers</strong> envoie de
                      vraies requêtes GET (jusqu&apos;à 50 chemins) à la cible.{" "}
                    </>
                  )}
                  Aucune opération destructive, aucune extraction de données, aucun
                  contournement d&apos;authentification -- mais ce n&apos;est plus une analyse
                  purement passive.
                </span>
                <Controller
                  control={control}
                  name="active_testing_confirmed"
                  render={({ field }) => (
                    <label className="flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        className="mt-0.5 size-4"
                        checked={field.value}
                        onChange={(event) => field.onChange(event.target.checked)}
                      />
                      <span>
                        Je comprends et j&apos;autorise l&apos;envoi de requêtes de test actives
                        à cette cible.
                      </span>
                    </label>
                  )}
                />
                {errors.active_testing_confirmed && (
                  <p className="text-sm text-destructive" role="alert">
                    {errors.active_testing_confirmed.message}
                  </p>
                )}
              </AlertDescription>
            </Alert>
          )}
          </div>

          {/*
           * Fixed footer: `shrink-0` keeps the "Annuler" / "Lancer le scan"
           * buttons visible below the scrollable body. `border-t` separates it
           * from the body.
           */}
          <div className="flex shrink-0 gap-2 border-t pt-4">
            <Button
              type="button"
              variant="outline"
              className="flex-1"
              onClick={() => setOpen(false)}
            >
              Annuler
            </Button>
            <Button type="submit" disabled={isSubmitting} className="flex-1">
              {isSubmitting && <Loader2 className="animate-spin" aria-hidden="true" />}
              Lancer le scan
            </Button>
          </div>
        </form>
      </SheetContent>
    </Sheet>
  );
}
