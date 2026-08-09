import { useEffect, useState } from 'react';
import { App } from './App';
import { AuthFlow } from './AuthFlow';
import { DeviceTrustBanner } from './DeviceTrustBanner';
import { authApi } from './auth-api';
import { bindStoredDevice } from './device-trust';
import './session.css';

function enrolled() {
  return localStorage.getItem('authlink.enrolled') === '1';
}

export function Root() {
  const [hash,setHash] = useState(location.hash || '#/feed');
  const [isEnrolled,setIsEnrolled] = useState(enrolled());
  const [checkingSession,setCheckingSession] = useState(true);
  const [sessionAuthenticated,setSessionAuthenticated] = useState(false);
  const [sessionTrusted,setSessionTrusted] = useState(false);
  const [loginError,setLoginError] = useState('');

  useEffect(()=>{
    const onHash = () => setHash(location.hash || '#/feed');
    addEventListener('hashchange',onHash);
    return ()=>removeEventListener('hashchange',onHash);
  },[]);

  useEffect(()=>{
    let live = true;
    const params = new URLSearchParams(location.search);
    const callbackState = params.get('authlink_login');
    const callbackReason = params.get('authlink_reason');

    async function verifySession() {
      const [oidcResult,sessionResult] = await Promise.allSettled([authApi.oidcStatus(), authApi.session()]);
      if(!live) return;
      const oidcReady = oidcResult.status === 'fulfilled'
        && oidcResult.value.configured
        && oidcResult.value.discovery_ready
        && oidcResult.value.pkce_s256;
      const authenticated = sessionResult.status === 'fulfilled' && sessionResult.value.authenticated;
      let trusted = authenticated && sessionResult.status === 'fulfilled' && sessionResult.value.trusted_device;

      setSessionAuthenticated(authenticated);
      setSessionTrusted(trusted);

      // OIDC proves a session; it does not mean the 16-step AuthLink ceremony is complete.
      // A first-time user returns to #/auth and continues the ceremony. Returning enrolled users go to Feed.
      if(!authenticated && oidcReady) {
        localStorage.removeItem('authlink.enrolled');
        setIsEnrolled(false);
      } else if(authenticated) {
        setIsEnrolled(enrolled());
      }

      // Existing browser keys may re-bind automatically. We never create a new device key here.
      if(authenticated && !trusted) {
        const rebound = await bindStoredDevice().catch(()=>null);
        if(!live) return;
        trusted = Boolean(rebound?.trusted);
        setSessionTrusted(trusted);
      }

      if(callbackState === 'error') {
        setLoginError(`Login protegido não concluído (${callbackReason ?? 'erro do provedor'}).`);
      } else if(callbackState === 'success' && !authenticated) {
        setLoginError('O provedor confirmou o login, mas a sessão AuthLink não pôde ser validada.');
      }

      if(callbackState) {
        const cleanHash = authenticated && enrolled() ? '#/feed' : '#/auth';
        history.replaceState({},'',`${location.pathname}${cleanHash}`);
        setHash(cleanHash);
      }
    }

    verifySession().finally(()=>{ if(live) setCheckingSession(false); });
    return ()=>{live=false};
  },[]);

  useEffect(()=>{
    if(hash === '#/auth/reset') {
      localStorage.removeItem('authlink.enrolled');
      setIsEnrolled(false);
      setSessionAuthenticated(false);
      setSessionTrusted(false);
      Promise.allSettled([authApi.logout(),authApi.reset()]).finally(()=>{ location.hash = '#/auth'; });
    }
  },[hash]);

  if(checkingSession) {
    return <div className="auth-session-check"><div className="auth-logo">⌁</div><b>AUTHLINK</b><span>Validando sessão e prova do dispositivo…</span></div>;
  }

  const trustBanner = sessionAuthenticated && !sessionTrusted
    ? <DeviceTrustBanner onTrusted={()=>setSessionTrusted(true)}/>
    : null;

  const authRoute = hash.startsWith('#/auth') || hash.startsWith('#/onboarding');
  if(!isEnrolled || authRoute) {
    return <>
      {loginError && <div className="auth-callback-error">{loginError}</div>}
      {trustBanner}
      <AuthFlow onComplete={()=>{
        localStorage.setItem('authlink.enrolled','1');
        setIsEnrolled(true);
        location.hash = '#/feed';
      }}/>
    </>;
  }

  return <>{trustBanner}<App/></>;
}
