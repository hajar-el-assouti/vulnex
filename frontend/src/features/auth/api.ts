import { apiFetch } from "@/lib/api/client";
import type { LoginRequest, MessageResponse, RegisterRequest, UserPublic } from "@/types/api";

export function registerUser(data: RegisterRequest): Promise<UserPublic> {
  return apiFetch<UserPublic>("/auth/register", { method: "POST", body: data });
}

export function loginUser(data: LoginRequest): Promise<UserPublic> {
  return apiFetch<UserPublic>("/auth/login", { method: "POST", body: data });
}

export function logoutUser(): Promise<MessageResponse> {
  return apiFetch<MessageResponse>("/auth/logout", { method: "POST" });
}

export function getCurrentUser(): Promise<UserPublic> {
  return apiFetch<UserPublic>("/auth/me", { method: "GET" });
}
