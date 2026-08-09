import { useEffect, useMemo, useState } from 'react';
import { api, type Capability } from './api';
import { Glyph, icons } from './icons';

type Route = 'feed'|'chat'|'apps'|'match'|'profile'|'security'|'passwords'|'photos'|'accounts'|'privacy'|'alerts'|'backup'|'panic'|'devices'|'integrations';
type SecondaryConfig = readonly [string,string,string];

const NAV: Array<{id: Route; label: string; icon: string}> = [
  { id:'feed', label:'Feed', icon:icons.home }, { id:'chat', label:'Chat', icon:icons.chat },
  { id:'apps', label:'Apps', icon:icons.apps }, { id:'match', label:'Match', icon:icons.match }, { id:'profile', label:'Perfil', icon:icons.profile }
];

function currentRoute(): Route {
  const v = location.hash.replace('#/','') as Route;
  return v || 'feed';
}

function AppShell({ route, onRoute, children }: { route: Route; onRoute:(r:Route)=>void; children: React.ReactNode }) {
  return <div className="app-shell">
    <header className="topbar">
      <button className="brand" onClick={()=>onRoute('feed')} aria-label="AuthLink início"><span className="brand-mark">⌁</span><span><b>AUTHLINK</b><small>AIIA SUITE</small></span></button>
      <div className="top-actions"><button aria-label="Buscar">{icons.search}</button><button aria-label="Notificações" onClick={()=>onRoute('alerts')}>{icons.bell}<i/></button><button className="avatar" onClick={()=>onRoute('profile')}>LM</button></div>
    </header>
    <main>{children}</main>
    <nav className="bottom-nav" aria-label="Navegação principal">{NAV.map(n=><button key={n.id} className={route===n.id?'active':''} onClick={()=>onRoute(n.id)}><span>{n.icon}</span><small>{n.label}</small>{n.id==='chat'&&<b>3</b>}</button>)}</nav>
  </div>
}

const shortcuts: Array<{route:Route; title:string; sub:string; icon:string; tone?:'blue'|'red'}> = [
  {route:'passwords',title:'Vault de Senhas',sub:'Senhas, passkeys e 2FA',icon:icons.lock},
  {route:'photos',title:'Cofre de Fotos',sub:'Mídia privada criptografada',icon:icons.photo},
  {route:'accounts',title:'Contas & Redes',sub:'Social, bancos e serviços',icon:icons.network,tone:'blue'},
  {route:'privacy',title:'Permissões',sub:'Câmera, mic, localização',icon:icons.shield},
  {route:'alerts',title:'Alertas',sub:'Ameaças e fraudes',icon:icons.bell},
  {route:'panic',title:'Modo Pânico',sub:'Proteção imediata',icon:icons.warning,tone:'red'},
];

function Hero({title,accent,subtitle}: {title:string;accent:string;subtitle:string}) { return <section className="hero"><div><h1>{title} <em>{accent}</em></h1><p>{subtitle}</p></div><div className="orb">⌁</div></section> }
function StatusPill({children,tone='green'}:{children:React.ReactNode;tone?:string}){return <span className={`status ${tone}`}>{children}</span>}
function Card({children,className=''}:{children:React.ReactNode;className?:string}){return <section className={`card ${className}`}>{children}</section>}

function Feed({go}:{go:(r:Route)=>void}) {
  return <><Hero title="Olá," accent="Lucas" subtitle="Sua identidade verificada conecta pessoas, apps e oportunidades com segurança."/>
    <Card className="message-card"><Glyph>◌</Glyph><div><h3>Mensagens não lidas</h3><p>3 novas mensagens de conexões</p></div><div className="avatars"><span>MS</span><span>RN</span><span>BL</span><b>3</b></div></Card>
    <div className="section-title"><h2>Proteção rápida</h2><button onClick={()=>go('security')}>Ver tudo →</button></div>
    <div className="shortcut-grid">{shortcuts.map(s=><button key={s.route} className="shortcut" onClick={()=>go(s.route)}><Glyph tone={s.tone==='blue'?'blue':s.tone==='red'?'red':'green'}>{s.icon}</Glyph><b>{s.title}</b><small>{s.sub}</small></button>)}</div>
    <div className="section-title"><h2>Feed</h2><button>Todos ⌄</button></div>
    <Post name="Mariana Santos" meta="Conexão de 2º grau · 2h" body="Compartilhou um case de sucesso em IA aplicada à saúde. Excelente leitura!" badge="24 curtidas · 8 comentários"/>
    <Post name="Rafael Nogueira" meta="Oportunidade verificada · 4h" body="Estamos contratando Engenheiro de IA · Remoto · Full-time · Sênior" badge="95% match" blue/>
    <Post name="Beatriz Lima" meta="Conexão de 1º grau · 6h" body="Enviou uma solicitação de conexão" badge="12 conexões em comum"/>
  </>
}
function Post({name,meta,body,badge,blue=false}:{name:string;meta:string;body:string;badge:string;blue?:boolean}){return <Card className="post"><div className={`face ${blue?'blue':''}`}>{name.split(' ').map(x=>x[0]).join('').slice(0,2)}</div><div><h3>{name}</h3><small className={blue?'blue-text':'green-text'}>{meta}</small><p>{body}</p><footer><span>♡</span><span>◌</span><b>{badge}</b></footer></div></Card>}

function Chat(){return <><Hero title="Chat" accent="seguro" subtitle="Conversas privadas, trabalho e comunidade em um só lugar."/><div className="segmented"><button className="active">Todas</button><button>Não lidas <b>3</b></button><button>Fixadas</button></div><Card><h3>Conversas protegidas com criptografia</h3><p>Mensagens, arquivos e chamadas usam canais protegidos e políticas por finalidade.</p></Card>{['Mariana Santos','Rafael Nogueira','Equipe Brainlink','Planner AI Support','Comunidade AuthLink'].map((n,i)=><Card className="conversation" key={n}><div className="face">{n.slice(0,2)}</div><div><h3>{n}</h3><p>{['Lucas, o case ficou incrível!','Nova oportunidade compatível com seu perfil.','Plano estratégico Q2 aprovado.','Seu plano foi atualizado com sucesso.','Novo recurso de identidade disponível.'][i]}</p></div><span>{i<2?i+1:''}</span></Card>)}</>}

function Apps({go, capabilities}:{go:(r:Route)=>void;capabilities:Capability[]}){return <><Hero title="Apps do" accent="plano" subtitle="Acesse softwares, segurança e integrações autorizadas pela sua identidade."/><div className="app-grid">{[
['Brainlink','IA estratégica'],['Planner AI','Planejamento'],['Vault','Cofre seguro'],['MediaFlow','Conteúdo com IA'],['AuthLink Chat','Mensagens'],['Earth','Geovisualização'],['Market','Oportunidades'],['Cursos','Aprendizado']
].map(([a,b],i)=><Card key={a} className="app-card"><Glyph tone={i===6?'blue':'green'}>{i%2?'▣':'⌬'}</Glyph><h3>{a}</h3><p>{b}</p><StatusPill>{i===6?'Upgrade':'Ativo'}</StatusPill></Card>)}</div><Card><div className="row"><div><small>Runtime</small><h3>Capacidades do gateway</h3></div><StatusPill>{capabilities.filter(x=>x.enabled).length} ativas</StatusPill></div><div className="chips">{capabilities.slice(0,8).map(c=><span key={c.id}>{c.title}</span>)}</div><button className="primary" onClick={()=>go('integrations')}>Integrações & Providers →</button></Card></>}

function Match(){return <><Hero title="Descobrir" accent="conexões" subtitle="Pessoas, projetos e oportunidades alinhados ao seu contexto."/><div className="segmented"><button className="active">Pessoas</button><button>Projetos</button><button>Oportunidades</button></div><Card className="match-card"><div className="portrait"><span>MS</span><StatusPill>Identidade verificada</StatusPill></div><h2>Mariana Santos ✓</h2><p>Arquiteta de Soluções de IA · NeuralSoft · Remoto</p><div className="chips"><span>IA Generativa</span><span>Arquitetura de Soluções</span><span>MLOps</span><span>Cloud</span></div><div className="match-meta"><div><b>Interesses em comum</b><p>IA responsável · produto · saúde</p></div><div><b>12 conexões em comum</b><p>2º grau</p></div></div><div className="match-actions"><button>×<small>Passar</small></button><button>▯<small>Salvar</small></button><button className="connect">＋<small>Conectar</small></button></div></Card></>}

function Profile({go}:{go:(r:Route)=>void}){return <><Hero title="Meu perfil /" accent="Identidade" subtitle="Sua identidade, seus dados, seu controle."/><Card className="profile-card"><div className="profile-head"><div className="avatar-big">LM</div><div><h2>Lucas ✓</h2><p>Engenheiro de IA · São Paulo, Brasil</p><StatusPill>Identidade verificada</StatusPill></div><div className="score"><b>92</b><small>Excelente</small></div></div><div className="stats"><span><b>128</b>Conexões</span><span><b>23</b>Oportunidades</span><span><b>7</b>Credenciais</span></div></Card><div className="section-title"><h2>Segurança e identidade</h2></div><div className="shortcut-grid">{shortcuts.concat([{route:'devices',title:'Dispositivos',sub:'Sessões confiáveis',icon:icons.device},{route:'backup',title:'Backup',sub:'Recuperação segura',icon:icons.cloud}]).map(s=><button key={s.route} className="shortcut" onClick={()=>go(s.route as Route)}><Glyph>{s.icon}</Glyph><b>{s.title}</b><small>{s.sub}</small></button>)}</div></>}

function SecurityHub({go}:{go:(r:Route)=>void}){return <><Hero title="Proteção" accent="total" subtitle="Proteja identidade, celular, contas, fotos e credenciais com políticas inteligentes."/><Card className="security-score"><div className="ring"><b>96%</b></div><div><h2>Excelente</h2><p>Nenhuma ameaça crítica ativa.</p></div><StatusPill>Tudo protegido</StatusPill></Card><div className="shortcut-grid">{shortcuts.concat([{route:'backup',title:'Backup & Recuperação',sub:'Restore seguro',icon:icons.cloud},{route:'devices',title:'Dispositivos & Sessões',sub:'Acessos confiáveis',icon:icons.device},{route:'integrations',title:'Integrações',sub:'Providers e apps',icon:icons.code}]).map(s=><button key={s.route} className="shortcut" onClick={()=>go(s.route as Route)}><Glyph tone={s.tone==='red'?'red':s.tone==='blue'?'blue':'green'}>{s.icon}</Glyph><b>{s.title}</b><small>{s.sub}</small></button>)}</div><Card><h2>Guardião IA</h2><p>Motor de risco por dispositivo, sessão, credencial, permissão e comportamento. Ações destrutivas sempre exigem política e confirmação apropriada.</p><div className="chips"><span>Detecção proativa</span><span>Análise comportamental</span><span>Resposta governada</span></div></Card></>}

const listData: Partial<Record<Route, Array<[string,string,string]>>> = {
 passwords:[['Google','lucas@exemplo.com','Forte'],['Instagram','@lucas','Forte'],['Banco','Conta principal','Revisar'],['GitHub','lucasdev','Forte']],
 accounts:[['Instagram','2FA ativo','Protegida'],['Gmail','Passkey','Protegida'],['Banco','Step-up','1 alerta'],['LinkedIn','2FA ativo','Protegida'],['Streaming','Senha','Atenção']],
 privacy:[['Câmera','2 apps ativos','Permitido'],['Microfone','1 app ativo','Permitido'],['Localização','3 apps ativos','Revisar'],['Contatos','5 apps ativos','Permitido'],['Arquivos','Acesso limitado','Seguro']],
 alerts:[['Login suspeito','Conta de e-mail','Bloqueado'],['Senha exposta','Credencial reutilizada','Atenção'],['Wi-Fi inseguro','Rede aberta','Atenção'],['Phishing','Link malicioso','Bloqueado']],
 devices:[['iPhone 15 Pro','Este dispositivo','98%'],['MacBook Pro','Ativo agora','96%'],['iPad Air','Ontem','94%'],['Windows PC','2 dias','90%']],
 integrations:[['GitHub','Conectado','Sync'],['GitLab','Conectado','Sync'],['Supabase','Conectado','Online'],['Vercel','Conectado','Sync'],['Netlify','Não conectado','Conectar'],['MCP Servers','Conectado','Local'],['Local Providers','Conectado','Local'],['Cloud Providers','Conectado','Online'],['Modules','Conectado','Sync'],['Sequencer','Conectado','Sync'],['Notes Workspace','Conectado','Local'],['Workbench / Preview','Conectado','Local']]
};

const screenConfig: Partial<Record<Route, SecondaryConfig>> = {
 passwords:['Vault de','Senhas','Proteção inteligente e criptografada para credenciais, passkeys, 2FA e dados sensíveis.'],
 photos:['Cofre de','Fotos','Fotos e vídeos privados com criptografia, biometria e controle de compartilhamento.'],
 accounts:['Contas &','Redes','Proteja contas sociais, e-mail, bancos e serviços conectados.'],
 privacy:['Permissões &','Privacidade','Controle o que cada app pode acessar no dispositivo.'],
 alerts:['Alertas &','Ameaças','Centro de monitoramento de riscos da sua identidade digital.'],
 backup:['Backup &','Recuperação','Backups criptografados e restauração governada.'],
 panic:['Modo','Pânico','Proteção de emergência para revogar acessos e ocultar conteúdo privado.'],
 devices:['Dispositivos &','Sessões','Gerencie dispositivos confiáveis e sessões ativas.'],
 integrations:['Integrações &','Providers','Conecte serviços, providers, MCP, módulos e ambientes autorizados.']
};

function ListScreen({route,go}:{route:Route;go:(r:Route)=>void}){
 const config: SecondaryConfig = screenConfig[route] ?? ['AuthLink','','Área protegida da sua identidade.'];
 if(route==='photos') return <><Hero title={config[0]} accent={config[1]} subtitle={config[2]}/><Card className="security-score"><div className="ring"><b>68%</b></div><div><h2>10,8 GB de 16 GB</h2><p>Backup criptografado · biometria ativa</p></div></Card><div className="photo-grid">{['Viagens','Família','Pessoal','Conteúdo sensível','Momentos íntimos','Documentos','Projetos privados','Novo álbum'].map((x,i)=><button key={x} className={`photo ${i>3?'locked':''}`}><span>{i===7?'＋':'▧'}</span><b>{x}</b><small>{i===7?'privado':`${42+i*31} itens`}</small></button>)}</div><Card><h2>Guardião IA de privacidade</h2><p>Classifica localmente, identifica conteúdo sensível e sugere proteção sem compartilhar mídia por padrão.</p></Card></>;
 if(route==='backup') return <><Hero title={config[0]} accent={config[1]} subtitle={config[2]}/><Card className="security-score"><div className="ring"><b>100%</b></div><div><h2>Backup atualizado</h2><p>Hoje · próximo automático amanhã</p></div><StatusPill>Tudo protegido</StatusPill></Card><Card><h2>Destinos</h2><div className="two-col"><button>▯<b>Local</b><small>Criptografado</small></button><button>☁<b>Nuvem segura</b><small>Sincronizado</small></button></div></Card><Card><h2>Pontos de restauração</h2>{['Hoje 08:45','Ontem 08:45','22/05 08:45'].map(x=><div className="list-row" key={x}><Glyph>{icons.cloud}</Glyph><span><b>{x}</b><small>Automático · 3,4 GB</small></span><button>Restaurar</button></div>)}</Card></>;
 if(route==='panic') return <><Hero title={config[0]} accent={config[1]} subtitle={config[2]}/><Card className="panic"><button className="panic-button">ATIVAR<br/>AGORA</button><div><h2>Proteção de emergência</h2><p>Bloquear apps, revogar sessões e acionar contatos confiáveis conforme regras pré-configuradas.</p></div></Card><div className="shortcut-grid">{[['Bloquear tudo','Apps e sessões'],['Ocultar mídia','Fotos e vídeos'],['Revogar acessos','Tokens ativos'],['Compartilhar localização','Somente se configurado'],['Contatar confiança','Canais aprovados']].map(([a,b])=><button className="shortcut" key={a}><Glyph tone="red">!</Glyph><b>{a}</b><small>{b}</small></button>)}</div></>;
 const data=listData[route]||[];
 return <><Hero title={config[0]} accent={config[1]} subtitle={config[2]}/><Card className="security-score"><div className="ring"><b>{route==='alerts'?'65':'96'}%</b></div><div><h2>{route==='alerts'?'Atenção':'Excelente'}</h2><p>{route==='integrations'?'Sincronização e integridade das conexões.':'Monitoramento e políticas em tempo real.'}</p></div><StatusPill tone={route==='alerts'?'amber':'green'}>{route==='alerts'?'Revisar':'Protegido'}</StatusPill></Card><Card className="list-card">{data.map(([a,b,c])=><div className="list-row" key={a}><Glyph tone={c.includes('alerta')||c==='Atenção'?'amber':'green'}>{route==='integrations'?icons.code:route==='devices'?icons.device:icons.shield}</Glyph><span><b>{a}</b><small>{b}</small></span><StatusPill tone={c==='Bloqueado'?'red':c==='Atenção'||c.includes('alerta')?'amber':'green'}>{c}</StatusPill><button>›</button></div>)}</Card><button className="primary" onClick={()=>go('security')}>Voltar à proteção total →</button></>;
}

export function App(){
 const [route,setRoute]=useState<Route>(currentRoute()); const [capabilities,setCapabilities]=useState<Capability[]>([]);
 const go=(r:Route)=>{location.hash=`#/${r}`;setRoute(r)};
 useEffect(()=>{const fn=()=>setRoute(currentRoute()); addEventListener('hashchange',fn); api.capabilities().then(x=>setCapabilities(x.capabilities)).catch(()=>setCapabilities([])); return()=>removeEventListener('hashchange',fn)},[]);
 const page=useMemo(()=>{switch(route){case'feed':return <Feed go={go}/>;case'chat':return <Chat/>;case'apps':return <Apps go={go} capabilities={capabilities}/>;case'match':return <Match/>;case'profile':return <Profile go={go}/>;case'security':return <SecurityHub go={go}/>;default:return <ListScreen route={route} go={go}/>}},[route,capabilities]);
 return <AppShell route={route} onRoute={go}>{page}</AppShell>;
}