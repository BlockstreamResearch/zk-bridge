export interface Wait {
  stage: 'finality' | 'claim' | 'confirm';
  elapsed: number;
  late: boolean;
}

export function depositWait(j: { status: string; created: number }, now: number): Wait | null;
export function duration(ms: number): string;
