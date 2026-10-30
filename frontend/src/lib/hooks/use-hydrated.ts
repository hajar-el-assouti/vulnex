"use client";

import { useSyncExternalStore } from "react";

/**
 * True only once the component has hydrated on the client.
 *
 * Several client components (theme toggle, theme select) must render a
 * neutral placeholder on the server/first paint and switch to the real
 * value right after hydration, to avoid a dark/light mismatch between the
 * server-rendered HTML and the client's actual theme. `useSyncExternalStore`
 * is the React-recommended way to do this "force an update once we're on
 * the client" sync without the `set-state-in-effect` lint warning that a
 * plain `useEffect(() => setMounted(true), [])` triggers.
 */
function subscribe() {
  return () => {};
}

function getClientSnapshot() {
  return true;
}

function getServerSnapshot() {
  return false;
}

export function useHydrated(): boolean {
  return useSyncExternalStore(subscribe, getClientSnapshot, getServerSnapshot);
}
