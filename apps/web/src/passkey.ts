import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

const PASSKEY_API = import.meta.env.VITE_AUTHLINK_PASSKEY_API ?? 'http://localhost:8790/api/v1';

export interface PasskeyCredentialSummary {
  id: string;
  credential_id: string;
  credential_device_type: string;
  credential_backed_up: boolean;
  transports: string[];
}

export interface PasskeyStatus {
  supported: boolean;
  registered: boolean;
  credentials: PasskeyCredentialSummary[];
  reason?: string;
}

interface CeremonyOptions {
  challenge_id: string;
  expires_in_seconds: number;
  options: Record<string, unknown>;
}

interface AssertionSuccess {
  verified: boolean;
  credential_id: string;
  auth_strength: 'passkey' | 'passkey+device-possession';
  user_verified: boolean;
  credential_device_type: string;
  credential_backed_up: boolean;
}

interface CredentialList {
  credentials: PasskeyCredentialSummary[];
}

class PasskeyApiError extends Error {
  constructor(public status: number, public code: string) {
    super(code);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${PASSKEY_API}${path}`, {
    ...init,
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
  });
  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('application/json') ? await response.json() : null;
  if (!response.ok) {
    throw new PasskeyApiError(response.status, body?.error ?? `HTTP_${response.status}`);
  }
  return body as T;
}

export function passkeysSupported() {
  return typeof window !== 'undefined'
    && window.isSecureContext
    && typeof PublicKeyCredential !== 'undefined'
    && typeof navigator.credentials !== 'undefined';
}

export async function passkeyStatus(): Promise<PasskeyStatus> {
  if (!passkeysSupported()) {
    return { supported: false, registered: false, credentials: [], reason: 'WebAuthn indisponível neste contexto' };
  }
  try {
    const result = await request<CredentialList>('/authlink/passkeys/credentials');
    return {
      supported: true,
      registered: result.credentials.length > 0,
      credentials: result.credentials,
    };
  } catch (error) {
    return {
      supported: true,
      registered: false,
      credentials: [],
      reason: error instanceof Error ? error.message : 'PASSKEY_STATUS_FAILED',
    };
  }
}

/**
 * Registration creates a credential but does not count as a current authentication
 * assertion. Call verifyWithPasskey() afterwards to elevate this session.
 */
export async function registerPasskey(): Promise<PasskeyCredentialSummary> {
  if (!passkeysSupported()) throw new Error('WEBAUTHN_UNAVAILABLE');
  const ceremony = await request<CeremonyOptions>('/authlink/passkeys/registration/options', {
    method: 'POST',
    body: '{}',
  });
  const credential = await startRegistration({ optionsJSON: ceremony.options as never });
  return request<PasskeyCredentialSummary>('/authlink/passkeys/registration/verify', {
    method: 'POST',
    body: JSON.stringify({ challenge_id: ceremony.challenge_id, response: credential }),
  });
}

export async function verifyWithPasskey(): Promise<AssertionSuccess> {
  if (!passkeysSupported()) throw new Error('WEBAUTHN_UNAVAILABLE');
  const ceremony = await request<CeremonyOptions>('/authlink/passkeys/authentication/options', {
    method: 'POST',
    body: '{}',
  });
  const assertion = await startAuthentication({ optionsJSON: ceremony.options as never });
  const result = await request<AssertionSuccess>('/authlink/passkeys/authentication/verify', {
    method: 'POST',
    body: JSON.stringify({ challenge_id: ceremony.challenge_id, response: assertion }),
  });
  if (!result.verified || !result.user_verified || !result.auth_strength.startsWith('passkey')) {
    throw new Error('PASSKEY_ASSERTION_NOT_VERIFIED');
  }
  return result;
}

export async function registerAndVerifyPasskey() {
  const credential = await registerPasskey();
  const assertion = await verifyWithPasskey();
  return { credential, assertion };
}

export async function revokePasskey(credentialId: string) {
  if (!credentialId) throw new Error('PASSKEY_CREDENTIAL_ID_REQUIRED');
  return request<{ credential_id: string; state: string }>('/authlink/passkeys/credentials/revoke', {
    method: 'POST',
    body: JSON.stringify({ credential_id: credentialId }),
  });
}
