import { useEffect, useState } from 'react';
import { App } from './App';
import { AuthFlow } from './AuthFlow';
import { authApi } from './auth-api';

function enrolled() {
  return localStorage.getItem('authlink.enrolled') === '1';
}

export function Root() {
  const [hash,setHash] = useState(location.hash || '#/feed');
  const [isEnrolled,setIsEnrolled] = useState(enrolled());
  const [checkingSession,setCheckingSession] = useState(true);
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

    Promise.allSettled([authApi.oidcStatus(), authApi.session()]).then(([oidcResult,sessionResult])=>{
      if(!live) return;
      const oidcReady = oidcResult.status === 'fulfilled'
        && oidcResult.value.configured
        && oidcResult.value.discovery_ready
        && oidcResult.value.pkce_s256;
      const authenticated = sessionResult.status === 'fulfilled' && sessionResult.value.authenticated;

      if(authenticated) {
        localStorage.setItem('authlink.enrolled','1');
        setIsEnrolled(true);
      } else if(oidcReady) {
        localStorage.removeItem('authlink.enrolled');
        setIsEnrolled(false);
      }

      if(callbackState === 'error') {
        setLoginError(`Login protegido não concluído (${callbackReason ?? 'erro do provedor'}).`);
      } else if(callbackState === 'success' && !authenticated) {
        setLoginError('O provedor confirmou o login, mas a sessão AuthLink não pôde ser validada.');
      }

      if(callbackState) {
        const cleanHash = authenticated ? '#/feed' : '#/auth';
        history.replaceState({},'',`${location.pathname}${cleanHash}`);
        setHash(cleanHash);
      }
    }).finally(()=>{ if(live) setCheckingSession(false); });

    return ()=>{live=false};
  },[]);

  useEffect(()=>{
    if(hash === '#/auth/reset') {
      localStorage.removeItem('authlink.enrolled');
      setIsEnrolled(false);
      Promise.allSettled([authApi.logout(),authApi.reset()]).finally(()=>{ location.hash = '#/auth'; });
    }
  },[hash]);

  if(checkingSession) {
    return <div className="auth-session-check"><div className="auth-logo">⌁</div><b>AUTHLINK</b><span>Validando sessão protegida…</span></div>;
  }

  const authRoute = hash.startsWith('#/auth') || hash.startsWith('#/onboarding');
  if(!isEnrolled || authRoute) {
    return <>
      {loginError && <div className="auth-callback-error">{loginError}</div>}
      <AuthFlow onComplete={()=>{
        localStorage.setItem('authlink.enrolled','1');
        setIsEnrolled(true);
        location.hash = '#/feed';
      }}/>
    </>;
  }

  return <App/>;
}
