import { z } from "zod";

/**
 * Mirrors app/schemas/scans.py::ScanCreateRequest. At least one module
 * must be selected; the backend re-validates every slug, so `min(1)` is
 * only a UX check.
 *
 * `active_testing_confirmed` must be true when an active module
 * (active_web_testing, discovery_fuzzing) is selected. The backend
 * checks this anyway (requires_active_confirmation on each module), even
 * for modules missing from this list; this only gives a clear error
 * before the request.
 */
const MODULES_REQUIRING_CONFIRMATION = ["active_web_testing", "discovery_fuzzing"];

export const scanCreateSchema = z
  .object({
    target_id: z.string().trim().min(1, "Choisissez une cible"),
    modules: z.array(z.string()).min(1, "Choisissez au moins un module"),
    active_testing_confirmed: z.boolean(),
  })
  .refine(
    (values) =>
      !values.modules.some((slug) => MODULES_REQUIRING_CONFIRMATION.includes(slug)) ||
      values.active_testing_confirmed,
    {
      message:
        "Confirmez que vous comprenez que ce module envoie des requêtes de test actives à la cible",
      path: ["active_testing_confirmed"],
    }
  );

export type ScanCreateFormValues = z.infer<typeof scanCreateSchema>;
