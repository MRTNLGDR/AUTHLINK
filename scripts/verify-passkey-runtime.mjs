import { existsSync, readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { spawn } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const envPath = join(root, '.env.local');
const rustBinary = process.platform === 'win32'
  ? join(root, 'target', 'debug', 'authlink-passkey-service.exe')
  : join(root, 'target', 'debug', 'authlink-passkey-service');

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

async function waitJson(url, validate, timeoutMs=30_000) {
  const deadline = Date.now()+timeoutMs;
  let lastError;
  while(Date.now()<deadline) {
    try {
      const response = await fetch(url,{cache:'no-store'});
      const body = await response.json();
      if(response.ok && validate(body)) return body;
    } catch(error) { lastError=error; }
    await new Promise(resolve=>setTimeout(resolve,250));
  }
  throw new Error(`Timed out waiting for ${url}${lastError?`: ${lastError.message}`:''}`);
}

function spawnCaptured(command,args,env) {
  const child = spawn(command,args,{cwd:root,env,stdio:['ignore','pipe','pipe'],shell:false});
  let stdout=''; let stderr='';
  child.stdout.on('data',chunk=>{stdout+=chunk.toString()});
  child.stderr.on('data',chunk=>{stderr+=chunk.toString()});
  return {child, logs:()=>({stdout,stderr})};
}

if(!existsSync(envPath)) throw new Error('Missing .env.local');
if(!existsSync(rustBinary)) throw new Error(`Missing Passkey binary: ${rustBinary}`);

const localEnv=parseEnv(readFileSync(envPath,'utf8'));
const env={
  ...process.env,
  ...localEnv,
  AUTHLINK_PASSKEY_ADDR:'127.0.0.1:8790',
  AUTHLINK_WEBAUTHN_VERIFIER_URL:'http://127.0.0.1:8791',
  AUTHLINK_WEBAUTHN_VERIFIER_HOST:'127.0.0.1',
  AUTHLINK_WEBAUTHN_VERIFIER_PORT:'8791',
  AUTHLINK_WEBAUTHN_RP_ID:'localhost',
  AUTHLINK_WEBAUTHN_ORIGIN:'http://localhost:5173',
  AUTHLINK_WEBAUTHN_RP_NAME:'AuthLink',
  RUST_LOG:'authlink_passkey_service=info',
};

const verifier=spawnCaptured(process.execPath,['services/webauthn-verifier/index.mjs'],env);
let passkey;
try {
  const verifierHealth=await waitJson(
    'http://127.0.0.1:8791/health',
    body=>body?.service==='authlink-webauthn-verifier' && body?.stateful===false
  );

  passkey=spawnCaptured(rustBinary,[],env);
  const passkeyHealth=await waitJson(
    'http://127.0.0.1:8790/api/v1/health',
    body=>body?.service==='authlink-passkey'
  );
  const status=await waitJson(
    'http://127.0.0.1:8790/api/v1/authlink/passkeys/status',
    body=>body?.database==='postgres'
      && body?.rp_id==='localhost'
      && body?.origin==='http://localhost:5173'
      && body?.user_verification==='required'
      && body?.assurance==='webauthn-assertion'
  );
  console.log(JSON.stringify({verifierHealth,passkeyHealth,status},null,2));
} catch(error) {
  console.error('VERIFIER LOGS',verifier.logs());
  if(passkey) console.error('PASSKEY LOGS',passkey.logs());
  throw error;
} finally {
  if(passkey && !passkey.child.killed) passkey.child.kill('SIGTERM');
  if(!verifier.child.killed) verifier.child.kill('SIGTERM');
}
