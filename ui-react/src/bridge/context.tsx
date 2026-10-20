import { type ReactNode, createContext, useContext, useEffect, useSyncExternalStore } from 'react';
import type { BridgeController } from './controller';
import type { BridgeState } from './types';

const Ctx = createContext<BridgeController | null>(null);

/** Provides `controller` to the tree and runs its polling while mounted. */
export function BridgeProvider({ controller, children }: { controller: BridgeController; children: ReactNode }) {
  useEffect(() => {
    controller.start();
    return () => controller.stop();
  }, [controller]);
  return <Ctx.Provider value={controller}>{children}</Ctx.Provider>;
}

export function useController(): BridgeController {
  const c = useContext(Ctx);
  if (!c) throw new Error('useController outside BridgeProvider');
  return c;
}

/** The controller's current state; re-renders on every change. */
export function useBridge(): BridgeState {
  const c = useController();
  return useSyncExternalStore(c.subscribe, c.getSnapshot, c.getSnapshot);
}
