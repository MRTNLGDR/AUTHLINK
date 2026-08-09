import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const envPath = join(root, '.env.local');

function parseEnv(text) {
  const values = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const index = line.indexOf('=');
    if (index > 0) values[line.slice(0,index)] = line.slice(index+1);
  }
  return values;
}

if(!existsSync(envPath)) throw new Error('Missing .env.local');
const env = parseEnv(readFileSync(envPath,'utf8'));
const issuer = (env.AUTHLINK_OIDC_ISSUER || '').replace(/\/$/,'');
if(!issuer) throw new Error('AUTHLINK_OIDC_ISSUER is not configured');

const discovery = await fetch(`${issuer}/.well-known/openid-configuration`, { cache:'no-store' });
if(!discovery.ok) throw new Error(`OIDC discovery failed: HTTP ${discovery.status}`);
const metadata = await discovery.json();
if(!metadata.code_challenge_methods_supported?.includes('S256')) {
  throw new Error('OIDC provider does not advertise PKCE S256');
}

const verifier = randomBytes(48).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
const authorize = new URL(metadata.authorization_endpoint);
authorize.searchParams.set('response_type','code');
authorize.searchParams.set('client_id',env.AUTHLINK_OIDC_CLIENT_ID);
authorize.searchParams.set('redirect_uri',env.AUTHLINK_OIDC_REDIRECT_URI);
authorize.searchParams.set('scope',env.AUTHLINK_OIDC_SCOPES || 'openid profile email');
authorize.searchParams.set('state','authlink-bootstrap-smoke');
authorize.searchParams.set('code_challenge',challenge);
authorize.searchParams.set('code_challenge_method','S256');

const response = await fetch(authorize, { redirect:'manual', cache:'no-store' });
if(response.status >= 400) {
  const body = await response.text();
  throw new Error(`Rauthy rejected bootstrapped client ${env.AUTHLINK_OIDC_CLIENT_ID}: HTTP ${response.status} ${body.slice(0,500)}`);
}

const location = response.headers.get('location') || '';
console.log(JSON.stringify({
  issuer: metadata.issuer,
  client_id: env.AUTHLINK_OIDC_CLIENT_ID,
  pkce_s256: true,
  authorization_http_status: response.status,
  redirected_to_login: Boolean(location),
}, null, 2));
