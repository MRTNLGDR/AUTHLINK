export type OnboardingStepId =
  | 'welcome'
  | 'account'
  | 'device-integrity'
  | 'face-capture'
  | 'liveness'
  | 'document'
  | 'identity-match'
  | 'consent'
  | 'passkey'
  | 'second-factor'
  | 'recovery'
  | 'vault-setup'
  | 'sovereign-identity'
  | 'avatar-opt-in'
  | 'audit-proof'
  | 'complete';

export type StepStatus = 'pending' | 'active' | 'complete' | 'skipped' | 'failed';

export interface OnboardingStep {
  id: OnboardingStepId;
  title: string;
  subtitle: string;
  status: StepStatus;
  required: boolean;
  purpose: string;
}

export interface OnboardingProgress {
  ceremony_id: string;
  current_index: number;
  completed: number;
  total: number;
  steps: OnboardingStep[];
  auth_strength: 'anonymous' | 'password' | 'passkey' | 'passkey-device' | 'step-up';
  trusted_device: boolean;
  risk_score: number;
}

export interface AdvanceResponse {
  accepted: boolean;
  progress: OnboardingProgress;
  message?: string | null;
}

export interface OidcStatus {
  configured: boolean;
  issuer?: string | null;
  client_id?: string | null;
  redirect_uri?: string | null;
  discovery_ready: boolean;
  pkce_s256: boolean;
}

export interface OidcStart {
  authorization_url: string;
  state: string;
}

export interface SessionSummary {
  authenticated: boolean;
  subject?: string | null;
  display_name?: string | null;
  auth_strength?: string | null;
  trusted_device: boolean;
  online: boolean;
}

const API = import.meta.env.VITE_AUTHLINK_API ?? 'http://127.0.0.1:8787/api/v1';

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...init,
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
  });
  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('application/json') ? await response.json() : null;
  if (!response.ok) {
    const message = body?.message ?? body?.error ?? `HTTP ${response.status}`;
    throw new Error(message);
  }
  return body as T;
}

export const authApi = {
  session: () => json<SessionSummary>('/authlink/session'),
  logout: () => json<void>('/authlink/session/logout', { method: 'POST', body: '{}' }),
  oidcStatus: () => json<OidcStatus>('/authlink/oidc/status'),
  oidcStart: () => json<OidcStart>('/authlink/oidc/start', { method: 'POST', body: '{}' }),
  progress: () => json<OnboardingProgress>('/authlink/onboarding'),
  advance: (step: OnboardingStepId, options?: { skip?: boolean; evidenceRef?: string }) =>
    json<AdvanceResponse>('/authlink/onboarding/advance', {
      method: 'POST',
      body: JSON.stringify({
        step,
        skip: options?.skip ?? false,
        evidence_ref: options?.evidenceRef ?? null,
      }),
    }),
  reset: () => json<OnboardingProgress>('/authlink/onboarding/reset', { method: 'POST', body: '{}' }),
};
