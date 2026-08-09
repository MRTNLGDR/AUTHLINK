import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const envPath = join(root, '.env.local');
const localRoot = join(root, '.authlink-local');
const rauthyBootstrapDir = join(localRoot, 'rauthy-bootstrap');
const composePath = join(root, 'infra', 'compose', 'docker-compose.dev.yml');
const modelPath = join(root, 'infra', 'openfga', 'model.json');
const migrationsDir = join(root, 'migrations');
const mode = process.argv[2] ?? 'all';

function parseEnv(text) {
  const values = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const index = line.indexOf('=');
    if (index < 1) continue;
    values[line.slice(0, index)] = line.slice(index + 1);
  }
  return values;
}

function renderEnv(values) {
  const groups = [
    ['# Generated local-only AuthLink environment. DO NOT COMMIT.', ['AUTHLINK_ENV','AUTHLINK_GATEWAY_ADDR','AUTHLINK_WEB_URL','AUTHLINK_DEFAULT_TENANT_ID']],
    ['# PostgreSQL authority', ['DATABASE_URL']],
    ['# OpenFGA ReBAC', ['AUTHLINK_POLICY_DEV_BYPASS','OPENFGA_API_URL','OPENFGA_STORE_ID','OPENFGA_AUTHORIZATION_MODEL_ID','OPENFGA_MODEL_HASH']],
    ['# Rauthy / OIDC + PKCE', ['AUTHLINK_OIDC_ISSUER','AUTHLINK_OIDC_CLIENT_ID','AUTHLINK_OIDC_REDIRECT_URI','AUTHLINK_OIDC_SCOPES','RAUTHY_ENC_KEYS','RAUTHY_ENC_KEY_ACTIVE','RAUTHY_ADMIN_PASSWORD']],
    ['# Web', ['VITE_AUTHLINK_API']],
  ];
  const lines = [];
  for (const [comment, keys] of groups) {
    lines.push(comment);
    for (const key of keys) lines.push(`${key}=${values[key] ?? ''}`);
    lines.push('');
  }
  return `${lines.join('\n').trim()}\n`;
}

function randomPassword() {
  return `AL-${randomBytes(18).toString('base64url')}-9a!`;
}

function randomRauthyKey() {
  // Rauthy expects the configured key value itself to be exactly 32 bytes.
  // 24 random bytes encoded as base64url produce exactly 32 ASCII bytes.
  return randomBytes(24).toString('base64url');
}

function validRauthyKeys(value) {
  if (!value) return false;
  return value.split(',').every(entry => {
    const slash = entry.indexOf('/');
    if (slash < 1) return false;
    const id = entry.slice(0, slash);
    const key = entry.slice(slash + 1);
    return id.length > 0 && Buffer.byteLength(key, 'utf8') === 32;
  });
}

function ensureEnv() {
  const env = existsSync(envPath) ? parseEnv(readFileSync(envPath, 'utf8')) : {};
  env.AUTHLINK_ENV ??= 'development';
  env.AUTHLINK_GATEWAY_ADDR ??= '127.0.0.1:8787';
  env.AUTHLINK_WEB_URL ??= 'http://localhost:5173';
  env.AUTHLINK_DEFAULT_TENANT_ID ??= '00000000-0000-7000-8000-000000000001';
  env.DATABASE_URL ??= 'postgres://authlink:authlink_dev_only@127.0.0.1:54329/authlink';
  env.AUTHLINK_POLICY_DEV_BYPASS ??= 'false';
  env.OPENFGA_API_URL ??= 'http://localhost:8080';
  env.OPENFGA_STORE_ID ??= '';
  env.OPENFGA_AUTHORIZATION_MODEL_ID ??= '';
  env.OPENFGA_MODEL_HASH ??= '';
  env.AUTHLINK_OIDC_ISSUER ??= 'http://localhost:8085/auth/v1';
  env.AUTHLINK_OIDC_CLIENT_ID ??= 'authlink-local';
  env.AUTHLINK_OIDC_REDIRECT_URI ??= 'http://localhost:8787/api/v1/authlink/oidc/callback';
  env.AUTHLINK_OIDC_SCOPES ??= 'openid profile email';
  env.VITE_AUTHLINK_API ??= 'http://localhost:8787/api/v1';
  env.RAUTHY_ENC_KEY_ACTIVE ??= 'authlink-local';
  if (!validRauthyKeys(env.RAUTHY_ENC_KEYS)) {
    env.RAUTHY_ENC_KEYS = `${env.RAUTHY_ENC_KEY_ACTIVE}/${randomRauthyKey()}`;
  }
  env.RAUTHY_ADMIN_PASSWORD ||= randomPassword();
  writeFileSync(envPath, renderEnv(env), { mode: 0o600 });
  return env;
}

function ensureRauthyBootstrap(env) {
  mkdirSync(rauthyBootstrapDir, { recursive: true, mode: 0o700 });

  const users = [{
    email: 'admin@authlink.local',
    password: { Plain: env.RAUTHY_ADMIN_PASSWORD },
    roles: ['rauthy_admin','admin','user'],
    groups: ['admin'],
    enabled: true,
    email_verified: true,
  }];

  const clients = [{
    id: env.AUTHLINK_OIDC_CLIENT_ID,
    name: 'AuthLink Local',
    redirect_uris: [env.AUTHLINK_OIDC_REDIRECT_URI],
    enabled: true,
    flows_enabled: ['authorization_code','refresh_token'],
    access_token_alg: 'EdDSA',
    id_token_alg: 'EdDSA',
    auth_code_lifetime: 60,
    access_token_lifetime: 3600,
    scopes: ['openid','profile','email'],
    default_scopes: ['openid','profile','email'],
    force_mfa: false,
  }];

  writeFileSync(join(rauthyBootstrapDir,'users.json'), `${JSON.stringify(users,null,2)}\n`, { mode: 0o600 });
  writeFileSync(join(rauthyBootstrapDir,'clients.json'), `${JSON.stringify(clients,null,2)}\n`, { mode: 0o600 });
}

function run(command, args, options = {}) {
  const stdio = options.capture
    ? ['ignore','pipe','pipe']
    : options.input !== undefined
      ? ['pipe','inherit','inherit']
      : 'inherit';
  const result = spawnSync(command, args, {
    cwd: root,
    stdio,
    encoding: 'utf8',
    env: options.env ?? process.env,
    input: options.input,
    shell: false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const details = options.capture ? `\n${result.stderr || result.stdout || ''}` : '';
    throw new Error(`${command} ${args.join(' ')} failed with code ${result.status}${details}`);
  }
  return result.stdout ?? '';
}

function composeArgs(...args) {
  return ['compose','--env-file',envPath,'-f',composePath,...args];
}

async function waitFor(url, validate = () => true, timeoutMs = 120_000) {
  const started = Date.now();
  let lastError;
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(url, { cache: 'no-store' });
      if (response.ok) {
        const text = await response.text();
        let body = text;
        try { body = JSON.parse(text); } catch {}
        if (validate(body, response)) return body;
      }
    } catch (error) { lastError = error; }
    await new Promise(resolve => setTimeout(resolve, 1500));
  }
  throw new Error(`Timed out waiting for ${url}${lastError ? `: ${lastError.message}` : ''}`);
}

async function jsonRequest(url, init) {
  const response = await fetch(url, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
  });
  const text = await response.text();
  let body = text;
  try { body = JSON.parse(text); } catch {}
  if (!response.ok) throw new Error(`${init?.method ?? 'GET'} ${url} -> ${response.status}: ${text}`);
  return body;
}

async function bootstrapOpenFga(env) {
  const base = env.OPENFGA_API_URL.replace(/\/$/, '');
  await waitFor(`${base}/healthz`, body => body?.status === 'SERVING');

  let storeId = env.OPENFGA_STORE_ID;
  if (storeId) {
    try {
      await jsonRequest(`${base}/stores/${storeId}`, { method: 'GET' });
    } catch {
      storeId = '';
    }
  }
  if (!storeId) {
    const store = await jsonRequest(`${base}/stores`, {
      method: 'POST',
      body: JSON.stringify({ name: 'AuthLink Local' }),
    });
    storeId = store.id;
    if (!storeId) throw new Error('OpenFGA did not return a store id');
  }

  const modelText = readFileSync(modelPath, 'utf8');
  const modelHash = createHash('sha256').update(modelText).digest('hex');
  let modelId = env.OPENFGA_AUTHORIZATION_MODEL_ID;
  if (!modelId || env.OPENFGA_MODEL_HASH !== modelHash) {
    const model = JSON.parse(modelText);
    const created = await jsonRequest(`${base}/stores/${storeId}/authorization-models`, {
      method: 'POST',
      body: JSON.stringify(model),
    });
    modelId = created.authorization_model_id;
    if (!modelId) throw new Error('OpenFGA did not return authorization_model_id');
  }

  env.OPENFGA_STORE_ID = storeId;
  env.OPENFGA_AUTHORIZATION_MODEL_ID = modelId;
  env.OPENFGA_MODEL_HASH = modelHash;
  writeFileSync(envPath, renderEnv(env), { mode: 0o600 });
  console.log(`OpenFGA ready: store=${storeId} model=${modelId}`);
}

function applyMigrations() {
  const files = readdirSync(migrationsDir).filter(name => name.endsWith('.sql')).sort();
  for (const name of files) {
    const sql = readFileSync(join(migrationsDir, name), 'utf8');
    console.log(`Applying ${name}`);
    run('docker', composeArgs('exec','-T','postgres','psql','-v','ON_ERROR_STOP=1','-U','authlink','-d','authlink'), { input: sql });
  }
}

async function verifyRauthy() {
  const metadata = await waitFor(
    'http://localhost:8085/auth/v1/.well-known/openid-configuration',
    body => body?.issuer && Array.isArray(body?.code_challenge_methods_supported) && body.code_challenge_methods_supported.includes('S256'),
    180_000,
  );
  console.log(`Rauthy OIDC ready: ${metadata.issuer}`);
}

async function main() {
  const env = ensureEnv();
  ensureRauthyBootstrap(env);
  console.log(`Local environment ready: ${envPath}`);
  console.log(`Local Rauthy bootstrap ready: ${rauthyBootstrapDir}`);
  if (mode === 'env') return;

  run('docker', ['compose','version']);
  run('docker', composeArgs('up','-d','postgres','openfga-migrate','openfga','rauthy'));
  await bootstrapOpenFga(env);
  applyMigrations();
  await verifyRauthy();

  console.log('\nAUTHLINK LOCAL READY');
  console.log('Web:       http://localhost:5173');
  console.log('Gateway:   http://localhost:8787/api/v1/health');
  console.log('Rauthy:    http://localhost:8085/auth/v1/admin');
  console.log('OpenFGA:   http://localhost:3000/playground');
  console.log('Admin:     admin@authlink.local');
  console.log(`Password:  ${env.RAUTHY_ADMIN_PASSWORD}`);
  console.log('\nRun: node scripts/dev-local.mjs');
}

main().catch(error => {
  console.error(`\nAuthLink bootstrap failed: ${error.stack || error.message || error}`);
  process.exitCode = 1;
});
