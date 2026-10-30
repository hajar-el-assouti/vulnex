"use client";

import { useCallback, useSyncExternalStore } from "react";

const COLLAPSE_STORAGE_KEY = "pentest-saas:sidebar-collapsed";
const listeners = new Set<() => void>();

function subscribe(onStoreChange: () => void) {
  listeners.add(onStoreChange);
  return () => listeners.delete(onStoreChange);
}

function getSnapshot(): boolean {
  try {
    return window.localStorage.getItem(COLLAPSE_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

function getServerSnapshot(): boolean {
  // Server/first paint always renders expanded; the real persisted
  // preference is only readable once we're on the client.
  return false;
}

/**
 * Per-viewer convenience only (sidebar collapsed/expanded), backed by
 * localStorage. Uses `useSyncExternalStore` rather than
 * state-initialized-in-an-effect, both to avoid the hydration mismatch a
 * direct read during render would cause, and the cascading-render lint
 * warning a `useEffect(() => setState(...), [])` triggers.
 */
export function useCollapsedSidebar(): [boolean, () => void] {
  const collapsed = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  const toggle = useCallback(() => {
    try {
      const next = !(window.localStorage.getItem(COLLAPSE_STORAGE_KEY) === "1");
      window.localStorage.setItem(COLLAPSE_STORAGE_KEY, next ? "1" : "0");
    } catch {
      // ignore -- storage unavailable (private mode, blocked, etc.)
    }
    for (const listener of listeners) listener();
  }, []);

  return [collapsed, toggle];
}
