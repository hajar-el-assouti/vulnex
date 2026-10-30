import { z } from "zod";

/** Mirrors the backend's actual constraint (app/schemas/auth.py:
 * `password: str = Field(min_length=10, max_length=128)`) -- not an
 * invented complexity rule. Client-side validation here is purely a UX
 * nicety (fail fast before a round trip); the backend's own validation
 * is still the real enforcement. */
export const loginSchema = z.object({
  email: z.string().trim().min(1, "L'email est requis").email("Email invalide"),
  password: z.string().min(1, "Le mot de passe est requis"),
});

export type LoginFormValues = z.infer<typeof loginSchema>;

export const registerSchema = z
  .object({
    email: z.string().trim().min(1, "L'email est requis").email("Email invalide"),
    password: z
      .string()
      .min(10, "Le mot de passe doit contenir au moins 10 caractères")
      .max(128, "Le mot de passe ne peut pas dépasser 128 caractères"),
    confirmPassword: z.string().min(1, "Veuillez confirmer le mot de passe"),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Les mots de passe ne correspondent pas",
    path: ["confirmPassword"],
  });

export type RegisterFormValues = z.infer<typeof registerSchema>;
