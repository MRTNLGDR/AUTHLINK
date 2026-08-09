import { existsSync, readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { spawn } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const envPath = join(root, '.env.local');
const args = process.argv.slice(2);

if (!args.length) {
  console.error('Usage: node scripts/run-local-command.mjs <command> [args...]');
  process.exit(2);
}
if (!existsSync(envPath)) {
  console.error('Missing .env.local. Run: node scripts/bootstrap-local.mjs all');
  process.exit(1);
}

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

const command = args[0];
const commandArgs = args.slice(1);
const child = spawn(command, commandArgs, {
  cwd: root,
  env: { ...process.env, ...parseEnv(readFileSync(envPath, 'utf8')) },
  stdio: 'inherit',
  shell: false,
});

let forwarding = false;
function forward(signal) {
  if (forwarding) return;
  forwarding = true;
  if (!child.killed) child.kill(process.platform === 'win32' ? undefined : signal);
}

process.on('SIGINT', () => forward('SIGINT'));
process.on('SIGTERM', () => forward('SIGTERM'));
child.on('error', error => {
  console.error(`Failed to start ${command}: ${error.message}`);
  process.exit(1);
});
child.on('exit', (code, signal) => {
  if (signal) process.exit(128);
  process.exit(code ?? 0);
});
