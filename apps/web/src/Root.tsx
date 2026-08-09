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

  useEffect(()=>{
    const onHash = () => setHash(location.hash || '#/feed');
    addEventListener('hashchange',onHash);
    return ()=>removeEventListener('hashchange',onHash);
  },[]);

  useEffect(()=>{
    if(hash === '#/auth/reset') {
      localStorage.removeItem('authlink.enrolled');
      setIsEnrolled(false);
      authApi.reset().catch(()=>undefined).finally(()=>{ location.hash = '#/auth'; });
    }
  },[hash]);

  const authRoute = hash.startsWith('#/auth') || hash.startsWith('#/onboarding');
  if(!isEnrolled || authRoute) {
    return <AuthFlow onComplete={()=>{
      localStorage.setItem('authlink.enrolled','1');
      setIsEnrolled(true);
      location.hash = '#/feed';
    }}/>;
  }

  return <App/>;
}
