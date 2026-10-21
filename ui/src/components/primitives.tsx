// Small building blocks shared by every panel. Fields carry their help and error by id (aria-describedby) and mark
// themselves invalid only while an error is shown.
import { type ComponentProps, type ReactNode, useId } from 'react';
import type { Tone } from '../bridge/journeys';
import { useController } from '../bridge/context';

export function ExtLink({ href, children, className }: { href: string; children: ReactNode; className?: string }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className={className}>
      {children}
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}

/** Text in which explorer and repository links (https://…) become links; nothing else is interpreted. */
export function Linkified({ text }: { text: string }) {
  const parts = text.split(/(https:\/\/[^\s)]+[^\s).,;])/g);
  return <>{parts.map((p, i) => (i % 2 ? <ExtLink key={i} href={p}>{p}</ExtLink> : p))}</>;
}

export function Pill({ tone, children }: { tone: Tone | 'idle'; children: ReactNode }) {
  return (
    <span className="pill" data-tone={tone}>
      <span className="dot" aria-hidden="true" />
      {children}
    </span>
  );
}

/** A verification mark: checked here and holding (true), checked and failing (false), or not checked here (null). */
export function Seal({ ok }: { ok: boolean | null }) {
  const label = ok === null ? 'Not checked here' : ok ? 'Checked' : 'Failed';
  return (
    <span className="seal" data-ok={ok === null ? 'none' : String(ok)} role="img" aria-label={label}>
      <svg viewBox="0 0 20 20" aria-hidden="true">
        <circle cx="10" cy="10" r="8.2" />
        {ok === true && <path d="M6 10.4l2.6 2.6L14.2 7.4" />}
        {ok === false && <path d="M7 7l6 6M13 7l-6 6" />}
      </svg>
    </span>
  );
}

interface Labelled {
  label: ReactNode;
  help?: ReactNode;
  error?: string;
}

/** The label, help and error around a control, with the ids that tie them to it. */
function FieldShell({ label, help, error, className, render }: Labelled & {
  className?: string;
  render: (a11y: { id: string; 'aria-describedby': string; 'aria-invalid': true | undefined }) => ReactNode;
}) {
  const id = useId();
  const described = [help ? `${id}-help` : '', `${id}-error`].filter(Boolean).join(' ');
  return (
    <div className={`field${className ? ` ${className}` : ''}`}>
      <label htmlFor={id}>{label}</label>
      {render({ id, 'aria-describedby': described, 'aria-invalid': error ? true : undefined })}
      {help && <p className="help" id={`${id}-help`}>{help}</p>}
      <p className="error" id={`${id}-error`} role="alert">{error}</p>
    </div>
  );
}

/** A labelled text input, optionally with a unit after it. */
export function Field({ label, help, error, unit, className, ...input }: Labelled & { unit?: string } & Omit<ComponentProps<'input'>, 'id'>) {
  return (
    <FieldShell label={label} help={help} error={error} className={className} render={(a11y) => (
      <div className={unit ? 'with-unit' : undefined}>
        <input className="mono" spellCheck={false} autoComplete="off" {...input} {...a11y} />
        {unit && <span className="unit" aria-hidden="true">{unit}</span>}
      </div>
    )} />
  );
}

export function TextAreaField({ label, help, error, className, ...area }: Labelled & Omit<ComponentProps<'textarea'>, 'id'>) {
  return (
    <FieldShell label={label} help={help} error={error} className={className} render={(a11y) => (
      <textarea className="mono" spellCheck={false} autoComplete="off" {...area} {...a11y} />
    )} />
  );
}

export function Button({ variant = 'default', className, ...props }: ComponentProps<'button'> & { variant?: 'primary' | 'default' | 'ghost' | 'small' }) {
  return <button type="button" className={`btn btn-${variant}${className ? ` ${className}` : ''}`} {...props} />;
}

/** A long value with a Copy button. */
export function CopyLine({ value, label }: { value: string; label: string }) {
  const c = useController();
  return (
    <div className="copyline">
      <code className="mono cli" aria-label={label}>{value}</code>
      <Button variant="small" onClick={() => void c.copy(value)}>Copy</Button>
    </div>
  );
}

/** A labelled list of what a step needs, kept as text so it survives copying and screen readers. */
export function Needs({ children }: { children: ReactNode }) {
  return (
    <>
      <span className="needs-label">Needs<span className="sr-only">:</span></span> {children}
    </>
  );
}

export function Hint({ children, live }: { children: ReactNode; live?: boolean }) {
  return <span className="hint" aria-live={live ? 'polite' : undefined}>{children}</span>;
}

/** One numbered step in a white strip inside the bridge tray. */
export function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <li className="step-row">
      <span className="numeral" aria-hidden="true">{n}</span>
      <div className="step-body">
        <h3>{title}</h3>
        {children}
      </div>
    </li>
  );
}
