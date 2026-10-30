import { z } from "zod";

/** Mirrors app/schemas/targets.py::TargetCreateRequest exactly (name
 * 1..255 chars, base_url 1..2048 chars and must be an absolute http(s)
 * URL, description optional up to 4000 chars). Client-side validation
 * is a UX nicety only -- the backend's own field_validator is the real
 * enforcement and will still reject anything this misses (e.g. a
 * syntactically valid but hostname-less URL). */
export const targetCreateSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "Le nom est requis")
    .max(255, "Le nom ne peut pas dépasser 255 caractères"),
  base_url: z
    .string()
    .trim()
    .min(1, "L'URL est requise")
    .max(2048, "L'URL ne peut pas dépasser 2048 caractères")
    .refine((value) => {
      try {
        const parsed = new URL(value);
        return (parsed.protocol === "http:" || parsed.protocol === "https:") && !!parsed.hostname;
      } catch {
        return false;
      }
    }, "L'URL doit être une URL http(s) absolue, ex: https://exemple.com"),
  description: z
    .string()
    .trim()
    .max(4000, "La description ne peut pas dépasser 4000 caractères")
    .optional()
    .or(z.literal("")),
});

export type TargetCreateFormValues = z.infer<typeof targetCreateSchema>;

/** Mirrors app/schemas/targets.py::TargetAuthorizeRequest. This records
 * a pointer to proof of authorization (a ticket id, a signed scope doc
 * reference) -- never proof itself, and never flips is_authorized on
 * its own; see that file's docstring. */
export const targetAuthorizeSchema = z.object({
  authorization_reference: z
    .string()
    .trim()
    .min(1, "La référence d'autorisation est requise")
    .max(512, "La référence ne peut pas dépasser 512 caractères"),
});

export type TargetAuthorizeFormValues = z.infer<typeof targetAuthorizeSchema>;
