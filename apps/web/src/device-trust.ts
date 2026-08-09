const DEVICE_API = import.meta.env.VITE_AUTHLINK_DEVICE_API ?? 'http://localhost:8789/api/v1';
const DB_NAME = 'authlink-device-trust-v1';
const STORE_NAME = 'device-keys';
const RECORD_KEY = 'primary';

export interface DeviceChallenge {
  challenge_id: string;
  action: 'enroll' | 'bind-session';
  message_b64: string;
  expires_in_seconds: number;
}

export interface DeviceSummary {
  id: string;
  device_public_id: string;
  platform: string;
  display_name?: string | null;
  trust_state: string;
  key_alg?: string | null;
  current_session: boolean;
}

export interface AssuranceResponse {
  device: DeviceSummary;
  auth_strength: string;
  trusted_device: boolean;
}

export interface DeviceList {
  devices: DeviceSummary[];
}

interface StoredDeviceKey {
  key: typeof RECORD_KEY;
  deviceId: string;
  privateKey: CryptoKey;
}

export interface DeviceTrustState {
  supported: boolean;
  trusted: boolean;
  device?: DeviceSummary;
  reason?: string;
}

class DeviceApiError extends Error {
  constructor(public status: number, public code: string) {
    super(code);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${DEVICE_API}${path}`, {
    ...init,
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
  });
  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('application/json') ? await response.json() : null;
  if (!response.ok) {
    throw new DeviceApiError(response.status, body?.error ?? `HTTP_${response.status}`);
  }
  return body as T;
}

export const deviceApi = {
  list: () => request<DeviceList>('/authlink/devices'),
  enrollChallenge: () => request<DeviceChallenge>('/authlink/devices/enroll/challenge', { method: 'POST', body: '{}' }),
  enrollComplete: (body: {
    challenge_id: string;
    public_key: JsonWebKey;
    signature_b64: string;
    platform: string;
    display_name?: string | null;
  }) => request<AssuranceResponse>('/authlink/devices/enroll/complete', { method: 'POST', body: JSON.stringify(body) }),
  bindChallenge: (deviceId: string) => request<DeviceChallenge>(`/authlink/devices/${deviceId}/challenge`, { method: 'POST', body: '{}' }),
  bindComplete: (deviceId: string, challengeId: string, signatureB64: string) =>
    request<AssuranceResponse>(`/authlink/devices/${deviceId}/verify`, {
      method: 'POST',
      body: JSON.stringify({ challenge_id: challengeId, signature_b64: signatureB64 }),
    }),
  revoke: (deviceId: string) => request<{ id: string; state: string }>(`/authlink/devices/${deviceId}/revoke`, { method: 'POST', body: '{}' }),
};

export function deviceCryptoSupported() {
  return typeof indexedDB !== 'undefined'
    && typeof crypto !== 'undefined'
    && Boolean(crypto.subtle)
    && window.isSecureContext;
}

export async function currentDeviceTrust(): Promise<DeviceTrustState> {
  if (!deviceCryptoSupported()) {
    return { supported: false, trusted: false, reason: 'WebCrypto/secure context indisponível' };
  }
  try {
    const list = await deviceApi.list();
    const current = list.devices.find(device => device.current_session && device.trust_state === 'trusted');
    if (current) return { supported: true, trusted: true, device: current };
    return { supported: true, trusted: false };
  } catch (error) {
    return { supported: true, trusted: false, reason: error instanceof Error ? error.message : 'DEVICE_STATUS_FAILED' };
  }
}

/**
 * Re-binds only a key that already exists in this browser. It never creates a
 * replacement key implicitly, so a revoked device cannot silently re-enroll.
 */
export async function bindStoredDevice(): Promise<DeviceTrustState> {
  if (!deviceCryptoSupported()) {
    return { supported: false, trusted: false, reason: 'WebCrypto/secure context indisponível' };
  }
  const record = await readStoredDevice();
  if (!record) return currentDeviceTrust();

  try {
    const challenge = await deviceApi.bindChallenge(record.deviceId);
    const signature = await sign(record.privateKey, challenge.message_b64);
    const result = await deviceApi.bindComplete(record.deviceId, challenge.challenge_id, signature);
    return { supported: true, trusted: result.trusted_device, device: result.device };
  } catch (error) {
    if (error instanceof DeviceApiError && [404, 409].includes(error.status)) {
      await clearStoredDevice();
      return { supported: true, trusted: false, reason: error.code };
    }
    return { supported: true, trusted: false, reason: error instanceof Error ? error.message : 'DEVICE_BIND_FAILED' };
  }
}

/** Explicit user action only. */
export async function enrollThisDevice(displayName?: string): Promise<DeviceTrustState> {
  if (!deviceCryptoSupported()) {
    return { supported: false, trusted: false, reason: 'WebCrypto/secure context indisponível' };
  }

  const existing = await readStoredDevice();
  if (existing) {
    const rebound = await bindStoredDevice();
    if (rebound.trusted) return rebound;
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify'],
  );
  const publicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  if (publicKey.kty !== 'EC' || publicKey.crv !== 'P-256' || !publicKey.x || !publicKey.y) {
    throw new Error('DEVICE_PUBLIC_KEY_EXPORT_INVALID');
  }

  const challenge = await deviceApi.enrollChallenge();
  const signature = await sign(keyPair.privateKey, challenge.message_b64);
  const result = await deviceApi.enrollComplete({
    challenge_id: challenge.challenge_id,
    public_key: {
      kty: 'EC',
      crv: 'P-256',
      x: publicKey.x,
      y: publicKey.y,
    },
    signature_b64: signature,
    platform: platformId(),
    display_name: displayName?.trim() || defaultDisplayName(),
  });

  try {
    await writeStoredDevice({ key: RECORD_KEY, deviceId: result.device.id, privateKey: keyPair.privateKey });
  } catch (error) {
    // Avoid leaving a server-trusted device whose private key this browser could not persist.
    await deviceApi.revoke(result.device.id).catch(() => undefined);
    throw error;
  }

  return { supported: true, trusted: result.trusted_device, device: result.device };
}

export async function forgetLocalDeviceKey() {
  await clearStoredDevice();
}

async function sign(privateKey: CryptoKey, messageB64: string) {
  const message = base64UrlDecode(messageB64);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    message,
  );
  const bytes = new Uint8Array(signature);
  if (bytes.byteLength !== 64) {
    throw new Error(`DEVICE_SIGNATURE_FORMAT_UNSUPPORTED_${bytes.byteLength}`);
  }
  return base64UrlEncode(bytes);
}

function platformId() {
  const raw = navigator.platform || 'web';
  const normalized = raw.toLowerCase().replace(/[^a-z0-9._:-]+/g, '-').replace(/^-+|-+$/g, '');
  return `webcrypto:${normalized || 'web'}`.slice(0, 48);
}

function defaultDisplayName() {
  const platform = navigator.platform || 'browser';
  return `Este dispositivo · ${platform}`.slice(0, 96);
}

function base64UrlDecode(value: string) {
  const padding = '='.repeat((4 - value.length % 4) % 4);
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + padding;
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64UrlEncode(bytes: Uint8Array) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'key' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('DEVICE_DB_OPEN_FAILED'));
  });
}

async function readStoredDevice(): Promise<StoredDeviceKey | null> {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get(RECORD_KEY);
      request.onsuccess = () => resolve((request.result as StoredDeviceKey | undefined) ?? null);
      request.onerror = () => reject(request.error ?? new Error('DEVICE_DB_READ_FAILED'));
    });
  } finally {
    db.close();
  }
}

async function writeStoredDevice(record: StoredDeviceKey) {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      transaction.objectStore(STORE_NAME).put(record);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error('DEVICE_DB_WRITE_FAILED'));
      transaction.onabort = () => reject(transaction.error ?? new Error('DEVICE_DB_WRITE_ABORTED'));
    });
  } finally {
    db.close();
  }
}

async function clearStoredDevice() {
  if (typeof indexedDB === 'undefined') return;
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      transaction.objectStore(STORE_NAME).delete(RECORD_KEY);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error('DEVICE_DB_DELETE_FAILED'));
    });
  } finally {
    db.close();
  }
}
