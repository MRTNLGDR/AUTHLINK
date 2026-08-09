import { existsSync, readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { spawn } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const envPath = join(root, '.env.local');
const binary = process.platform === 'win32'
  ? join(root, 'target', 'debug', 'authlink-vault-service.exe')
  : join(root, 'target', 'debug', 'authlink-vault-service');

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

async function waitJson(url, validate, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { cache: 'no-store' });
      const body = await response.json();
      if (response.ok && validate(body)) return body;
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for ${url}${lastError ? `: ${lastError.message}` : ''}`);
}

if (!existsSync(envPath)) throw new Error('Missing .env.local');
if (!existsSync(binary)) throw new Error(`Missing Vault binary: ${binary}`);

const localEnv = parseEnv(readFileSync(envPath, 'utf8'));
const child = spawn(binary, [], {
  cwd: root,
  env: { ...process.env, ...localEnv, RUST_LOG: 'authlink_vault_service=info' },
  stdio: ['ignore', 'pipe', 'pipe'],
  shell: false,
});
let stdout = '';
let stderr = '';
child.stdout.on('data', chunk => { stdout += chunk.toString(); });
child.stderr.on('data', chunk => { stderr += chunk.toString(); });

try {
  const health = await waitJson('http://127.0.0.1:8788/api/v1/health', body => body?.service === 'authlink-vault');
  const status = await waitJson(
    'http://127.0.0.1:8788/api/v1/authlink/vault/status',
    body => body?.encryption === 'XCHACHA20-POLY1305'
      && body?.active_key_version === Number(localEnv.AUTHLINK_VAULT_ACTIVE_KEY_VERSION)
      && body?.database === 'postgres'
  );
  console.log(JSON.stringify({ health, status }, null, 2));
} catch (error) {
  console.error(stdout);
  console.error(stderr);
  throw error;
} finally {
  if (!child.killed) child.kill('SIGTERM');
}
