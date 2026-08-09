import { useCallback, useEffect, useState } from 'react';
import {
  passkeyStatus,
  registerPasskey,
  verifyWithPasskey,
  type PasskeyStatus,
} from './passkey';
import './passkey.css';

export function PasskeyBanner({ onVerified }: { onVerified?: (strength:string)=>void }) {
  const [state,setState] = useState<PasskeyStatus>({ supported:true, registered:false, credentials:[] });
  const [busy,setBusy] = useState(true);
  const [error,setError] = useState('');
  const [verified,setVerified] = useState(false);

  const refresh = useCallback(async()=>{
    setBusy(true);
    try { setState(await passkeyStatus()); }
    finally { setBusy(false); }
  },[]);

  useEffect(()=>{ void refresh(); },[refresh]);

  async function register() {
    setBusy(true); setError('');
    try {
      await registerPasskey();
      const next = await passkeyStatus();
      setState(next);
    } catch(e) {
      setError(e instanceof Error ? e.message : 'PASSKEY_REGISTRATION_FAILED');
    } finally { setBusy(false); }
  }

  async function verify() {
    setBusy(true); setError('');
    try {
      const result = await verifyWithPasskey();
      setVerified(true);
      onVerified?.(result.auth_strength);
    } catch(e) {
      setError(e instanceof Error ? e.message : 'PASSKEY_ASSERTION_FAILED');
    } finally { setBusy(false); }
  }

  return <div className={verified?'passkey-banner passkey-banner-ok':'passkey-banner'}>
    <div className="passkey-banner-icon">⌁</div>
    <div className="passkey-banner-copy">
      <b>{verified?'Passkey verificada nesta sessão':state.registered?'Passkey cadastrada':'Adicionar uma passkey real'}</b>
      <small>{verified
        ? 'Uma assertion WebAuthn com verificação do usuário elevou a assurance desta sessão.'
        : state.registered
          ? 'Cadastro não é autenticação. Use sua passkey agora para produzir uma assertion WebAuthn desta sessão.'
          : 'O autenticador cria a chave privada; o AuthLink guarda apenas credential ID, public key COSE e counter.'}</small>
      {(error||state.reason)&&<em>{error||state.reason}</em>}
    </div>
    <div className="passkey-banner-actions">
      {!state.registered && <button disabled={busy||!state.supported} onClick={register}>{busy?'Processando…':'Cadastrar passkey'}</button>}
      {state.registered && !verified && <button disabled={busy||!state.supported} onClick={verify}>{busy?'Verificando…':'Verificar com passkey'}</button>}
      {verified && <span>VERIFIED</span>}
    </div>
  </div>;
}
