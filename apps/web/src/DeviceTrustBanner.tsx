import { useCallback, useEffect, useState } from 'react';
import {
  bindStoredDevice,
  currentDeviceTrust,
  enrollThisDevice,
  type DeviceTrustState,
} from './device-trust';
import './device-trust.css';

export function DeviceTrustBanner({ onTrusted }: { onTrusted?: () => void }) {
  const [state,setState] = useState<DeviceTrustState>({ supported:true, trusted:false });
  const [busy,setBusy] = useState(true);
  const [error,setError] = useState('');

  const refresh = useCallback(async () => {
    setBusy(true);
    setError('');
    try {
      let next = await currentDeviceTrust();
      if(next.supported && !next.trusted) {
        next = await bindStoredDevice();
      }
      setState(next);
      if(next.trusted) onTrusted?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Falha ao verificar dispositivo');
    } finally {
      setBusy(false);
    }
  },[onTrusted]);

  useEffect(()=>{ void refresh(); },[refresh]);

  async function enroll() {
    setBusy(true);
    setError('');
    try {
      const next = await enrollThisDevice();
      setState(next);
      if(next.trusted) onTrusted?.();
    } catch(e) {
      setError(e instanceof Error ? e.message : 'Falha ao vincular dispositivo');
    } finally {
      setBusy(false);
    }
  }

  if(state.trusted) {
    return <div className="device-trust device-trust-ok">
      <div className="device-trust-icon">✓</div>
      <div><b>Dispositivo com prova de posse</b><small>{state.device?.display_name ?? 'Chave P-256 vinculada à sessão atual'}</small></div>
      <span>TRUSTED</span>
    </div>;
  }

  return <div className="device-trust">
    <div className="device-trust-icon">◇</div>
    <div className="device-trust-copy">
      <b>Proteja esta sessão com uma chave deste dispositivo</b>
      <small>{state.supported
        ? 'O AuthLink gera uma chave P-256 no WebCrypto, mantém a privada neste navegador e prova posse por challenge assinado.'
        : 'Este contexto não oferece WebCrypto + IndexedDB seguros para criar uma chave local.'}</small>
      {(error || state.reason) && <em>{error || state.reason}</em>}
    </div>
    <button disabled={busy || !state.supported} onClick={enroll}>
      {busy?'Verificando…':'Vincular este dispositivo'}
    </button>
  </div>;
}
