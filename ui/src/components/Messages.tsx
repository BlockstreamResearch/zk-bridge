import { useEffect, useState } from 'react';
import { useBridge } from '../bridge/context';

/** The last toast, for five seconds, and a polite live region that announces each message once. */
export function Messages() {
  const { toast, announcement } = useBridge();
  const [expired, setExpired] = useState<number | null>(null);
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setExpired(toast.id), 5000);
    return () => clearTimeout(t);
  }, [toast]);
  return (
    <>
      <div className="sr-only" aria-live="polite">{announcement?.text}</div>
      {/* The live region above announces it; the toast itself is not a second live region. */}
      {toast && expired !== toast.id && <div className="toast">{toast.text}</div>}
    </>
  );
}
