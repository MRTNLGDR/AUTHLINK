import { createServer } from 'node:http';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

const HOST = process.env.AUTHLINK_WEBAUTHN_VERIFIER_HOST ?? '127.0.0.1';
const PORT = Number(process.env.AUTHLINK_WEBAUTHN_VERIFIER_PORT ?? 8791);
const MAX_BODY = 2 * 1024 * 1024;

function b64urlToBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid base64url input');
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

function bytesToB64url(value) {
  return Buffer.from(value).toString('base64url');
}

function requiredString(value, name, max = 512) {
  if (typeof value !== 'string' || !value || value.length > max) throw new Error(`${name} invalid`);
  return value;
}

function safeCredentialList(value) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 64) throw new Error('credential list invalid');
  return value.map(entry => ({
    id: requiredString(entry?.id, 'credential.id', 2048),
    transports: Array.isArray(entry?.transports) ? entry.transports : undefined,
  }));
}

async function registrationOptions(input) {
  const challenge = b64urlToBytes(requiredString(input.challenge_b64, 'challenge_b64', 256));
  const userID = b64urlToBytes(requiredString(input.user_id_b64, 'user_id_b64', 256));
  if (challenge.byteLength !== 32) throw new Error('challenge must be 32 bytes');
  if (userID.byteLength < 1 || userID.byteLength > 64) throw new Error('user id length invalid');

  return generateRegistrationOptions({
    rpName: requiredString(input.rp_name, 'rp_name', 96),
    rpID: requiredString(input.rp_id, 'rp_id', 253),
    userID,
    userName: requiredString(input.user_name, 'user_name', 128),
    userDisplayName: requiredString(input.user_display_name, 'user_display_name', 128),
    challenge,
    timeout: 120000,
    attestationType: 'none',
    excludeCredentials: safeCredentialList(input.exclude_credentials),
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
    },
    supportedAlgorithmIDs: [-7, -8, -257],
  });
}

async function verifyRegistration(input) {
  const result = await verifyRegistrationResponse({
    response: input.response,
    expectedChallenge: requiredString(input.expected_challenge, 'expected_challenge', 256),
    expectedOrigin: requiredString(input.expected_origin, 'expected_origin', 512),
    expectedRPID: requiredString(input.expected_rp_id, 'expected_rp_id', 253),
    requireUserPresence: true,
    requireUserVerification: true,
    supportedAlgorithmIDs: [-7, -8, -257],
  });
  if (!result.verified || !result.registrationInfo) return { verified: false };
  const info = result.registrationInfo;
  return {
    verified: true,
    credential: {
      id: info.credential.id,
      public_key_b64: bytesToB64url(info.credential.publicKey),
      counter: info.credential.counter,
      transports: info.credential.transports ?? [],
    },
    aaguid: info.aaguid,
    attestation_format: info.fmt,
    user_verified: info.userVerified,
    credential_device_type: info.credentialDeviceType,
    credential_backed_up: info.credentialBackedUp,
    origin: info.origin,
    rp_id: info.rpID ?? input.expected_rp_id,
  };
}

async function authenticationOptions(input) {
  const challenge = b64urlToBytes(requiredString(input.challenge_b64, 'challenge_b64', 256));
  if (challenge.byteLength !== 32) throw new Error('challenge must be 32 bytes');
  return generateAuthenticationOptions({
    rpID: requiredString(input.rp_id, 'rp_id', 253),
    challenge,
    timeout: 120000,
    userVerification: 'required',
    allowCredentials: safeCredentialList(input.allow_credentials),
  });
}

async function verifyAuthentication(input) {
  const credential = input.credential;
  if (!credential || typeof credential !== 'object') throw new Error('credential invalid');
  const counter = Number(credential.counter);
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error('credential counter invalid');
  const result = await verifyAuthenticationResponse({
    response: input.response,
    expectedChallenge: requiredString(input.expected_challenge, 'expected_challenge', 256),
    expectedOrigin: requiredString(input.expected_origin, 'expected_origin', 512),
    expectedRPID: requiredString(input.expected_rp_id, 'expected_rp_id', 253),
    credential: {
      id: requiredString(credential.id, 'credential.id', 2048),
      publicKey: b64urlToBytes(requiredString(credential.public_key_b64, 'credential.public_key_b64', 8192)),
      counter,
      transports: Array.isArray(credential.transports) ? credential.transports : undefined,
    },
    requireUserVerification: true,
  });
  return {
    verified: result.verified,
    new_counter: result.authenticationInfo.newCounter,
    credential_id: result.authenticationInfo.credentialID,
    user_verified: result.authenticationInfo.userVerified,
    credential_device_type: result.authenticationInfo.credentialDeviceType,
    credential_backed_up: result.authenticationInfo.credentialBackedUp,
    origin: result.authenticationInfo.origin,
    rp_id: result.authenticationInfo.rpID,
  };
}

const handlers = new Map([
  ['/registration/options', registrationOptions],
  ['/registration/verify', verifyRegistration],
  ['/authentication/options', authenticationOptions],
  ['/authentication/verify', verifyAuthentication],
]);

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw Object.assign(new Error('body too large'), { status: 413 });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function json(res, status, body) {
  const encoded = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': encoded.length,
    'cache-control': 'no-store',
  });
  res.end(encoded);
}

const server = createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return json(res, 200, {
      status: 'ok',
      service: 'authlink-webauthn-verifier',
      library: '@simplewebauthn/server',
      version: '13.3.2',
      stateful: false,
    });
  }
  if (req.method !== 'POST') return json(res, 404, { error: 'NOT_FOUND' });
  const handler = handlers.get(req.url);
  if (!handler) return json(res, 404, { error: 'NOT_FOUND' });
  try {
    const body = await readJson(req);
    const output = await handler(body);
    return json(res, 200, output);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'verification failed';
    const status = Number(error?.status) || 422;
    console.warn(JSON.stringify({ event: 'webauthn-verifier-rejected', path: req.url, message }));
    return json(res, status, { error: 'WEBAUTHN_VERIFICATION_REJECTED', message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(JSON.stringify({ service: 'authlink-webauthn-verifier', host: HOST, port: PORT }));
});
