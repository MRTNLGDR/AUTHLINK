import { useEffect, useState } from 'react';
import { authApi, type OnboardingProgress, type OnboardingStepId } from './auth-api';
import './auth.css';

const FALLBACK_STEPS: Array<[OnboardingStepId,string,string,boolean,string]> = [
  ['welcome','Bem-vindo ao AuthLink','Sua identidade universal começa neste dispositivo.',true,'identity.enroll'],
  ['account','Criar conta ou entrar','Vincule seu AuthLink ID e escolha seu acesso inicial.',true,'identity.account'],
  ['device-integrity','Integridade do dispositivo','Validamos postura e sinais de confiança do aparelho.',true,'device.trust'],
  ['face-capture','Captura facial','Mapeamento facial para proofing e referência PERZON autorizada.',true,'biometric.enroll'],
  ['liveness','Prova de vida','Confirme presença real com liveness/PAD.',true,'biometric.liveness'],
  ['document','Documento oficial','Validação documental quando a finalidade exigir.',false,'identity.document'],
  ['identity-match','Correspondência de identidade','Combinamos evidências e risco antes de elevar confiança.',true,'identity.match'],
  ['consent','Consentimentos','Escolha finalidade, retenção e uso de cada dado.',true,'consent.grant'],
  ['passkey','Cadastrar passkey','A passkey protegida pelo sistema vira o fator principal.',true,'credential.passkey'],
  ['second-factor','Segundo fator','Adicione security key ou método alternativo forte.',false,'credential.second-factor'],
  ['recovery','Recuperação','Gere códigos e configure contatos confiáveis.',true,'identity.recovery'],
  ['vault-setup','Configurar Vault','Crie seu cofre e a hierarquia local de chaves.',true,'vault.bootstrap'],
  ['sovereign-identity','Identidade soberana','Revise credenciais, dispositivos e escopos.',true,'identity.activate'],
  ['avatar-opt-in','Avatar PEZON','Opcional: autorize uma referência separada para seu gêmeo digital.',false,'avatar.reference'],
  ['audit-proof','Prova e auditoria','Registramos o resultado mínimo e a trilha de consentimento.',true,'audit.write'],
  ['complete','Acesso liberado','Sua identidade está pronta. Você entra direto no Feed.',true,'session.activate'],
];

function fallbackProgress(index=0): OnboardingProgress {
  return {
    ceremony_id: 'offline-preview', current_index:index, completed:index, total:FALLBACK_STEPS.length,
    auth_strength:index>8?'passkey-device':'anonymous', trusted_device:index>2, risk_score:index>2?8:24,
    steps:FALLBACK_STEPS.map(([id,title,subtitle,required,purpose],i)=>({
      id,title,subtitle,required,purpose,status:i<index?'complete':i===index?'active':'pending'
    }))
  };
}

const GLYPH: Record<OnboardingStepId,string> = {
  welcome:'⌁', account:'◎', 'device-integrity':'▣', 'face-capture':'◉', liveness:'◇', document:'▤',
  'identity-match':'✓', consent:'◫', passkey:'⌁', 'second-factor':'✦', recovery:'♢', 'vault-setup':'▰',
  'sovereign-identity':'⬡', 'avatar-opt-in':'◉', 'audit-proof':'⛓', complete:'✓'
};

export function AuthFlow({ onComplete }: { onComplete:()=>void }) {
  const [progress,setProgress] = useState<OnboardingProgress>(()=>fallbackProgress());
  const [online,setOnline] = useState(false);
  const [busy,setBusy] = useState(true);
  const [error,setError] = useState('');
  const [email,setEmail] = useState('');
  const [consent,setConsent] = useState({security:true, biometric:true, avatar:false, analytics:false});

  useEffect(()=>{
    let live=true;
    authApi.progress().then(p=>{if(live){setProgress(p);setOnline(true)}}).catch(()=>{if(live)setOnline(false)}).finally(()=>{if(live)setBusy(false)});
    return ()=>{live=false};
  },[]);

  const step = progress.steps[progress.current_index] ?? progress.steps.at(-1)!;
  const percent = Math.round((progress.completed / progress.total)*100);
  const canSkip = !step.required;
  const isLast = step.id === 'complete';

  async function advance(skip=false) {
    setError(''); setBusy(true);
    try {
      if (online) {
        const r = await authApi.advance(step.id,{skip,evidenceRef: evidenceFor(step.id)});
        setProgress(r.progress);
        if (r.progress.completed >= r.progress.total) finish();
      } else {
        const next = Math.min(progress.completed+1, progress.total);
        setProgress(fallbackProgress(next));
        if(next>=progress.total) finish();
      }
    } catch (e) { setError(e instanceof Error?e.message:'Falha ao avançar'); }
    finally { setBusy(false); }
  }

  function evidenceFor(id:OnboardingStepId) {
    if(id==='consent') return `consent:${Object.entries(consent).filter(([,v])=>v).map(([k])=>k).join(',')}`;
    return undefined;
  }

  function finish(){ localStorage.setItem('authlink.enrolled','1'); onComplete(); }

  return <div className="auth-shell">
    <header className="auth-topbar">
      <div className="auth-brand"><span className="auth-logo">⌁</span><span><b>AUTHLINK</b><small>AIIA SUITE</small></span></div>
      <div className="auth-trust"><i className={online?'online':'offline'}/><span>{online?'Gateway protegido':'Modo local'}</span></div>
    </header>

    <main className="auth-main">
      <section className="auth-progress">
        <div><span>CONFIGURAÇÃO DE IDENTIDADE</span><b>{progress.completed}/{progress.total}</b></div>
        <div className="auth-progress-track"><i style={{width:`${percent}%`}}/></div>
      </section>

      <section className="auth-stage">
        <aside className="auth-visual">
          <div className={`auth-orb auth-orb-${step.id}`}><span>{GLYPH[step.id]}</span><i/><i/><i/></div>
          <div className="auth-metrics">
            <div><small>TRUST</small><b>{100-progress.risk_score}%</b></div>
            <div><small>RISK</small><b>{progress.risk_score}</b></div>
            <div><small>DEVICE</small><b>{progress.trusted_device?'OK':'CHECK'}</b></div>
          </div>
        </aside>

        <article className="auth-panel">
          <div className="auth-kicker"><span>ETAPA {Math.min(progress.current_index+1,progress.total)}</span><b>{step.purpose}</b></div>
          <h1>{step.title}</h1>
          <p className="auth-subtitle">{step.subtitle}</p>
          <StepBody id={step.id} email={email} setEmail={setEmail} consent={consent} setConsent={setConsent}/>
          {error&&<div className="auth-error">{error}</div>}
          <div className="auth-actions">
            {canSkip && <button className="auth-secondary" disabled={busy} onClick={()=>advance(true)}>Agora não</button>}
            <button className="auth-primary" disabled={busy || (step.id==='account'&&!email)} onClick={()=>advance(false)}>
              {busy?'Processando…':isLast?'Entrar no AuthLink':'Continuar'} <span>→</span>
            </button>
          </div>
          <footer className="auth-foot"><span>Zero Trust</span><span>Purpose-bound</span><span>Auditável</span><span>Criptografia ponta a ponta</span></footer>
        </article>
      </section>
    </main>
  </div>
}

type Consent = {security:boolean;biometric:boolean;avatar:boolean;analytics:boolean};
function StepBody({id,email,setEmail,consent,setConsent}:{id:OnboardingStepId;email:string;setEmail:(v:string)=>void;consent:Consent;setConsent:(v:Consent)=>void}) {
  switch(id){
    case 'welcome': return <div className="auth-feature-grid"><Feature icon="◉" title="Uma identidade" text="SSO, passkeys, consentimentos e apps da suíte."/><Feature icon="⌁" title="Segurança contínua" text="Guardian avalia sessão, dispositivo e risco."/><Feature icon="↯" title="Local-first" text="Funciona localmente e reconcilia quando online."/></div>;
    case 'account': return <div className="auth-form"><label>AuthLink ID ou e-mail<input value={email} onChange={e=>setEmail(e.target.value)} placeholder="voce@exemplo.com" autoComplete="username"/></label><button className="method"><span>⌁</span><b>Entrar com passkey existente</b><small>Preferencial</small></button><button className="method"><span>✉</span><b>Continuar com e-mail</b><small>Conta nova ou recuperação</small></button></div>;
    case 'device-integrity': return <Checklist items={['Sistema operacional suportado','Boot e integridade verificados','Keystore/Secure Enclave disponível','Sem sinais críticos de comprometimento']}/>;
    case 'face-capture': return <div className="face-capture"><div className="face-frame"><div className="face-silhouette">◉</div><i className="scan-line"/></div><div className="capture-stats"><span>68 pontos-chave</span><span>Qualidade excelente</span><span>Frame bruto temporário</span></div></div>;
    case 'liveness': return <><Checklist items={['Olhe para a câmera','Gire levemente o rosto','Acompanhe o ponto luminoso','PAD ativo contra replay/máscara']}/><div className="pulse-line"><i/><i/><i/><i/><i/><i/><i/></div></>;
    case 'document': return <div className="document-box"><span>▤</span><h3>Documento oficial</h3><p>Use câmera ou arquivo autorizado. O documento bruto não vai para blockchain.</p><button>Capturar documento</button></div>;
    case 'identity-match': return <div className="match-proof"><div className="match-ring"><b>99,87%</b><small>similaridade</small></div><Checklist items={['Face detectada','Liveness confirmado','Evidência documental consistente','Nenhum conflito crítico']}/></div>;
    case 'consent': return <div className="consent-list"><Toggle label="Segurança e prevenção de fraude" detail="Obrigatório para proteger sessão e dispositivo" checked={consent.security} disabled onChange={()=>{}}/><Toggle label="Biometria para identity proofing" detail="Template segregado e purpose-bound" checked={consent.biometric} onChange={v=>setConsent({...consent,biometric:v})}/><Toggle label="Referência para avatar PEZON" detail="Uso separado do login" checked={consent.avatar} onChange={v=>setConsent({...consent,avatar:v})}/><Toggle label="Telemetria de produto" detail="Sem biometria, saúde ou finanças" checked={consent.analytics} onChange={v=>setConsent({...consent,analytics:v})}/></div>;
    case 'passkey': return <div className="key-card"><div className="key-icon">⌁</div><div><h3>Passkey protegida pelo dispositivo</h3><p>Chave privada permanece no autenticador do sistema. O AuthLink recebe apenas material público e attestation permitida.</p></div><span className="recommended">RECOMENDADO</span></div>;
    case 'second-factor': return <div className="auth-feature-grid"><Feature icon="◇" title="Security key" text="FIDO2/NFC/USB para step-up."/><Feature icon="123" title="TOTP" text="Código temporário como fallback."/><Feature icon="⌁" title="Outro dispositivo" text="Aprovação por sessão confiável."/></div>;
    case 'recovery': return <div className="recovery"><div className="codes">{['A9FK-2TQM','P7LX-8NAD','C4ZR-1WKS','M8UE-5VHP'].map(x=><code key={x}>{x}</code>)}</div><p>Guarde fora do dispositivo. Códigos nunca são enviados em analytics.</p></div>;
    case 'vault-setup': return <div className="vault-setup"><div className="vault-icon">▰</div><Checklist items={['Master key gerada localmente','Envelope encryption pronta','Autolock configurado','Backup opcional separado']}/><div className="vault-bar"><i style={{width:'82%'}}/></div></div>;
    case 'sovereign-identity': return <div className="identity-card"><div className="identity-badge">⬡</div><div><h2>Identidade verificada</h2><p>Passkey + dispositivo + proofing + consentimentos.</p><div className="identity-chips"><span>SSO</span><span>OpenFGA</span><span>Trusted device</span><span>Purpose grants</span></div></div></div>;
    case 'avatar-opt-in': return <div className="avatar-opt"><div className="avatar-ghost">◉</div><div><h3>Transformar referência autorizada em avatar</h3><p>PEZON recebe uma referência consentida; não recebe sua chave de autenticação nem vira autoridade de login.</p></div></div>;
    case 'audit-proof': return <div className="proof-list"><Proof label="Cerimônia" value="019…f72"/><Proof label="Consent root" value="sha256: 8a9…d13"/><Proof label="Audit batch" value="merkle: 42e…a07"/><Proof label="Chain anchor" value="Opcional / sem PII"/></div>;
    case 'complete': return <div className="complete-card"><div className="complete-check">✓</div><h2>Autenticação máxima ativada</h2><p>Seu AuthLink está pronto para proteger sua identidade e abrir todos os apps autorizados da AIIA.</p><div className="identity-chips"><span>Passkey</span><span>Device trust</span><span>Guardian</span><span>Vault</span><span>Audit</span></div></div>;
  }
}

function Feature({icon,title,text}:{icon:string;title:string;text:string}){return <div className="auth-feature"><span>{icon}</span><h3>{title}</h3><p>{text}</p></div>}
function Checklist({items}:{items:string[]}){return <div className="checklist">{items.map(x=><div key={x}><span>✓</span><b>{x}</b><small>Verificado</small></div>)}</div>}
function Toggle({label,detail,checked,onChange,disabled=false}:{label:string;detail:string;checked:boolean;onChange:(v:boolean)=>void;disabled?:boolean}){return <button className="consent-row" disabled={disabled} onClick={()=>onChange(!checked)}><div><b>{label}</b><small>{detail}</small></div><span className={checked?'toggle on':'toggle'}><i/></span></button>}
function Proof({label,value}:{label:string;value:string}){return <div className="proof-row"><span>{label}</span><code>{value}</code><b>✓</b></div>}
