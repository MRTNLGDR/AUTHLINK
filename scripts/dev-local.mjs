import { existsSync, readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { spawn } from 'node:child_process';

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

if (!existsSync(envPath)) {
  console.error('Missing .env.local. Run: node scripts/bootstrap-local.mjs all');
  process.exit(1);
}

const localEnv = parseEnv(readFileSync(envPath,'utf8'));
for (const required of [
  'DATABASE_URL','OPENFGA_API_URL','OPENFGA_STORE_ID','OPENFGA_AUTHORIZATION_MODEL_ID',
  'AUTHLINK_VAULT_KEYS','AUTHLINK_VAULT_ACTIVE_KEY_VERSION'
]) {
  if (!localEnv[required]) {
    console.error(`Missing ${required} in .env.local. Run: node scripts/bootstrap-local.mjs all`);
    process.exit(1);
  }
}

const childEnv = {
  ...process.env,
  ...localEnv,
  RUST_LOG: process.env.RUST_LOG ?? 'authlink_gateway=info,authlink_vault_service=info,tower_http=info'
};
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const cargo = process.platform === 'win32' ? 'cargo.exe' : 'cargo';
const children = [];

function start(label, command, args) {
  const child = spawn(command,args,{cwd:root,env:childEnv,stdio:'inherit',shell:false});
  children.push(child);
  child.on('exit',(code,signal)=>{
    if(code && code !== 0) {
      console.error(`${label} stopped with code ${code}${signal?` signal ${signal}`:''}`);
      shutdown(code);
    }
  });
  child.on('error',error=>{
    console.error(`${label} failed to start: ${error.message}`);
    shutdown(1);
  });
  return child;
}

function openBrowser(url) {
  const command = process.platform === 'win32' ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c','start','',url] : [url];
  const child = spawn(command,args,{cwd:root,stdio:'ignore',detached:true,shell:false});
  child.unref();
}

let shuttingDown = false;
function shutdown(code=0) {
  if(shuttingDown) return;
  shuttingDown=true;
  for(const child of children) {
    if(!child.killed) child.kill(process.platform === 'win32' ? undefined : 'SIGTERM');
  }
  setTimeout(()=>process.exit(code),250).unref();
}

process.on('SIGINT',()=>shutdown(0));
process.on('SIGTERM',()=>shutdown(0));

console.log('Starting AuthLink Gateway + Vault + Web…');
console.log('Web:     http://localhost:5173');
console.log('Gateway: http://localhost:8787/api/v1/health');
console.log('Vault:   http://localhost:8788/api/v1/health');
console.log('Press Ctrl+C to stop app processes. Infra remains running.');

start('gateway',cargo,['run','-p','authlink-gateway']);
start('vault',cargo,['run','-p','authlink-vault-service']);
start('web',npm,['run','dev','-w','@authlink/web','--','--host','0.0.0.0']);

setTimeout(()=>openBrowser('http://localhost:5173'),5000).unref();
