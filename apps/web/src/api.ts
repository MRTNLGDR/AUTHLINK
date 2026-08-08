export type Capability = { id: string; title: string; group: string; enabled: boolean };
export type SessionSummary = { subject: string; authStrength: string; trustedDevice: boolean; online: boolean };

const base = '/api/v1';

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${base}${path}`, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => getJson<{ status: string; service: string }>('/health'),
  capabilities: () => getJson<{ capabilities: Capability[] }>('/authlink/capabilities'),
  session: () => getJson<SessionSummary>('/authlink/session'),
};
