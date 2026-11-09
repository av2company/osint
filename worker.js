/* OSINT AV2 - Cloudflare Worker
 * Deploy: dash.cloudflare.com > Workers > Create > cole este arquivo > Deploy.
 * Vazamentos de e-mail: funciona sem chave (XposedOrNot). Para somar o Have I Been Pwned, adicione o secret HIBP_KEY
 * em Settings > Variables and Secrets (chave de haveibeenpwned.com/API/Key). Depois coloque a URL do Worker em OSINT_API no index.html.
 *
 * GET /username?u=NOME[&k=0&n=10] -> { username, results:[{name,status,url,info,cat}] }  status: found | not_found | unknown | na (nome inválido naquele site, ignorado)
 * GET /email?e=EMAIL   -> { email, breached, breaches:[...], pastes:[...], rep:{reputação, perfis ligados ao e-mail} | null }   (XposedOrNot + HIBP quando houver HIBP_KEY)
 *
 * GET /stealer?e=EMAIL -> { email, found, stealers:[{date,family,computer,os,ip,antiviruses,corporate,user,logins,passwords}] }   (Hudson Rock Cavalier, gratuito, sem chave; dados já mascarados pela fonte)
 *
 * GET /phone?n=NUMERO -> { number, configured, valid, carrier, type, country, countryCode, region, source }   (Veriphone; precisa do secret VERIPHONE_KEY, chave gratuita em veriphone.io. Sem a chave devolve configured:false)
 *
 * GET /ip?i=IP -> { geo, flags, greynoise, otx, passiveDns, reverseIp, tor, sources }   (ip-api, GreyNoise, OTX, HackerTarget, Tor; sem chave)
 *
 * GET /accounts?e=EMAIL -> { email, results:[{name,status,url}] }   status: found | not_found | unknown (checagens passivas de cadastro, sem enviar e-mail ao dono)
 *
 * GET /status -> saúde das fontes (veja a camada de proteção no final do arquivo)
 *
 * Só consulta páginas/APIs públicas. "unknown" = o site bloqueou, limitou ou não respondeu (nunca é tratado como "não existe").
 * Para restringir quem pode chamar o Worker, crie a variável ALLOWED_ORIGINS (ex.: https://seudominio.com.br). */
const ALLOW_ORIGIN='*';
const UA='Mozilla/5.0 (compatible; OSINT-AV2/2.0)';
// [nome, url de checagem, url do perfil (opcional), marcador de "não existe" (opcional), modo do marcador: 'eq' = igualdade exata (opcional), status extra que significa "não existe" (opcional), status que significa "existe" (opcional), 1 = modo estrito: só 404/410 conta como "não existe", resposta 200 vira "unknown" (opcional)]
const SITES=[
 ['Instagram','https://www.instagram.com/{u}/','','','',0,0,1],
 ['X (Twitter)','https://x.com/{u}','','','',0,0,1],
 ['Facebook','https://www.facebook.com/{u}','','','',0,0,1],
 ['Threads','https://www.threads.net/@{u}','','','',0,0,1],
 ['Kwai','https://www.kwai.com/@{u}','','','',0,0,1],
 ['GitHub','https://github.com/{u}'],
 ['GitLab','https://gitlab.com/api/v4/users?username={u}','https://gitlab.com/{u}','[]','eq'],
 ['Bitbucket','https://bitbucket.org/{u}/'],
 ['Codeberg','https://codeberg.org/api/v1/users/{u}','https://codeberg.org/{u}'],
 ['Gitee','https://gitee.com/{u}'],
 ['Reddit','https://www.reddit.com/user/{u}/about.json','https://www.reddit.com/user/{u}'],
 ['TikTok','https://www.tiktok.com/@{u}','','"statusCode":10221'],
 ['Twitch','https://passport.twitch.tv/usernames/{u}?client_id=kimne78kx3ncx6brgo4mv6wki5h1ko','https://www.twitch.tv/{u}','','',204],
 ['YouTube','https://www.youtube.com/@{u}'],
 ['Pinterest','https://www.pinterest.com/{u}/'],
 ['Medium','https://medium.com/@{u}'],
 ['DEV','https://dev.to/{u}'],
 ['Tumblr','https://{u}.tumblr.com'],
 ['SoundCloud','https://soundcloud.com/{u}'],
 ['Last.fm','https://www.last.fm/user/{u}'],
 ['Vimeo','https://vimeo.com/{u}'],
 ['Behance','https://www.behance.net/{u}'],
 ['Dribbble','https://dribbble.com/{u}'],
 ['Speaker Deck','https://speakerdeck.com/{u}'],
 ['Patreon','https://www.patreon.com/{u}'],
 ['Linktree','https://linktr.ee/{u}'],
 ['Gravatar','https://gravatar.com/{u}'],
 ['Replit','https://replit.com/@{u}'],
 ['Hugging Face','https://huggingface.co/{u}'],
 ['npm','https://registry.npmjs.org/-/user/org.couchdb.user:{u}','https://www.npmjs.com/~{u}'],
 ['PyPI','https://pypi.org/user/{u}/'],
 ['Scratch','https://api.scratch.mit.edu/users/{u}','https://scratch.mit.edu/users/{u}'],
 ['Mastodon.social','https://mastodon.social/@{u}'],
 ['Bluesky','https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social','https://bsky.app/profile/{u}.bsky.social','','',400],
 ['Keybase','https://keybase.io/{u}'],
 ['About.me','https://about.me/{u}'],
 ['Pastebin','https://pastebin.com/u/{u}'],
 ['Docker Hub','https://hub.docker.com/v2/users/{u}/','https://hub.docker.com/u/{u}'],
 ['Wikipedia','https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={u}&format=json','https://en.wikipedia.org/wiki/User:{u}','"missing"'],
 ['Duolingo','https://www.duolingo.com/2017-06-30/users?username={u}','https://www.duolingo.com/profile/{u}','"users":[]'],
 ['Steam','https://steamcommunity.com/id/{u}','','The specified profile could not be found'],
 ['Hacker News','https://hacker-news.firebaseio.com/v0/user/{u}.json','https://news.ycombinator.com/user?id={u}','null','eq'],
 ['Chess.com','https://api.chess.com/pub/player/{l}','https://www.chess.com/member/{l}'],
 ['Lichess','https://lichess.org/api/user/{u}','https://lichess.org/@/{u}'],
 ['Telegram','https://t.me/{u}','','<title>Telegram: Contact @'],
 ['Snapchat','https://www.snapchat.com/add/{u}'],
 ['VK','https://vk.com/{u}'],
 ['Ko-fi','https://ko-fi.com/{u}'],
 ['Buy Me a Coffee','https://www.buymeacoffee.com/{u}'],
 ['Substack','https://{u}.substack.com/'],
 ['Blogger','https://{u}.blogspot.com/'],
 ['Itch.io','https://{u}.itch.io/'],
 ['Bandcamp','https://{u}.bandcamp.com/'],
 ['CodePen','https://codepen.io/{u}'],
 ['Codeforces','https://codeforces.com/api/user.info?handles={u}','https://codeforces.com/profile/{u}','','',400],
 ['Mixcloud','https://api.mixcloud.com/{u}/','https://www.mixcloud.com/{u}/'],
 ['Dailymotion','https://api.dailymotion.com/user/{u}?fields=screenname,id','https://www.dailymotion.com/{u}'],
 ['Genius','https://genius.com/{u}'],
 ['Letterboxd','https://letterboxd.com/{u}/'],
 ['MyAnimeList','https://myanimelist.net/profile/{u}'],
 ['Trakt','https://trakt.tv/users/{u}'],
 ['Minecraft','https://api.mojang.com/users/profiles/minecraft/{u}','https://namemc.com/profile/{u}'],
 ['SourceForge','https://sourceforge.net/u/{u}/'],
 ['Launchpad','https://launchpad.net/~{u}'],
 ['Hackaday','https://hackaday.io/{u}'],
 ['Instructables','https://www.instructables.com/member/{u}/'],
 ['Wattpad','https://www.wattpad.com/user/{u}'],
 ['Disqus','https://disqus.com/by/{u}/'],
 ['SlideShare','https://www.slideshare.net/{u}'],
 ['Issuu','https://issuu.com/{u}'],
 ['Imgur','https://imgur.com/user/{u}'],
 ['Giphy','https://giphy.com/{u}'],
 ['Flipboard','https://flipboard.com/@{u}']
];
const CATS={'Redes sociais':'Instagram,X (Twitter),Facebook,Threads,Kwai,TikTok,Snapchat,Telegram,VK,Bluesky,Mastodon.social,Tumblr,Pinterest,Reddit,Flipboard,Disqus','Desenvolvimento':'GitHub,GitLab,Bitbucket,Codeberg,Gitee,DEV,Replit,Hugging Face,npm,PyPI,Docker Hub,Keybase,Hacker News,CodePen,Codeforces,SourceForge,Launchpad,Hackaday,Instructables,Pastebin','Vídeo e música':'YouTube,Twitch,Vimeo,Dailymotion,SoundCloud,Last.fm,Mixcloud,Bandcamp,Genius','Criação e portfólio':'Behance,Dribbble,Medium,Speaker Deck,Patreon,Ko-fi,Buy Me a Coffee,Substack,Blogger,Linktree,About.me,Gravatar,Imgur,Giphy,Wattpad,Issuu,SlideShare,Wikipedia','Jogos e hobbies':'Steam,Chess.com,Lichess,Minecraft,Scratch,Itch.io,Letterboxd,MyAnimeList,Trakt,Duolingo'};
const CATOF={};for(const c in CATS)CATS[c].split(',').forEach(n=>{CATOF[n]=c});
// Formato válido do username em cada site: se não bate, o site é ignorado ("na") em vez de gastar consulta e voltar "não verificável".
const HN=/^[a-z0-9-]{1,63}$/i;
const RX={'Instagram':/^[a-z0-9._]{1,30}$/i,'Threads':/^[a-z0-9._]{1,30}$/i,'X (Twitter)':/^\w{1,15}$/,'TikTok':/^[a-z0-9._]{2,24}$/i,'GitHub':/^[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}$/i,'Reddit':/^[\w-]{3,20}$/,'Twitch':/^\w{4,25}$/,'YouTube':/^[\w.-]{3,30}$/,'Telegram':/^[a-z]\w{4,31}$/i,'Snapchat':/^[a-z][\w.-]{2,14}$/i,'Bluesky':/^[a-z0-9-]{3,63}$/i,'Mastodon.social':/^\w{1,30}$/,'Steam':/^\w{3,32}$/,'Minecraft':/^\w{3,16}$/,'DEV':/^\w{2,30}$/,'Keybase':/^\w{2,16}$/,'Hacker News':/^[\w-]{2,15}$/,'Docker Hub':/^[a-z0-9_]{4,30}$/i,'Tumblr':HN,'Substack':HN,'Blogger':HN,'Itch.io':HN,'Bandcamp':HN};
const yr=t=>{const d=new Date(t);return isNaN(d)?'':d.getFullYear()};
const jn=(a)=>a.filter(Boolean).join(' · ');
const INFO={
 'Reddit':j=>{const d=j&&j.data||{};return jn([d.is_suspended?'suspenso':'',(d.link_karma||0)+(d.comment_karma||0)?'karma '+((d.link_karma||0)+(d.comment_karma||0)):'',d.created_utc?'desde '+yr(d.created_utc*1000):''])},
 'Bluesky':j=>jn([j.displayName,j.followersCount!=null?j.followersCount+' seguidores':'',j.postsCount!=null?j.postsCount+' posts':'',j.createdAt?'desde '+yr(j.createdAt):'']),
 'Docker Hub':j=>jn([j.full_name,j.location,j.date_joined?'desde '+yr(j.date_joined):'']),
 'Hacker News':j=>jn(['karma '+j.karma,j.created?'desde '+yr(j.created*1000):'']),
 'Lichess':j=>jn([j.title,j.count&&j.count.all!=null?j.count.all+' partidas':'',j.createdAt?'desde '+yr(j.createdAt):'']),
 'Chess.com':j=>jn([j.name,j.followers!=null?j.followers+' seguidores':'',j.joined?'desde '+yr(j.joined*1000):'']),
 'GitLab':j=>Array.isArray(j)&&j[0]?jn([j[0].name,j[0].state]):'',
 'Codeberg':j=>jn([j.full_name,j.location,j.followers_count!=null?j.followers_count+' seguidores':'',j.created?'desde '+yr(j.created):'']),
 'Codeforces':j=>{const x=(j.result||[])[0]||{};return jn([x.rank,x.rating?'rating '+x.rating:'',x.country])},
 'Mixcloud':j=>jn([j.name,j.follower_count!=null?j.follower_count+' seguidores':'',j.created_time?'desde '+yr(j.created_time):'']),
 'Dailymotion':j=>j.screenname||'',
 'Scratch':j=>jn([j.profile&&j.profile.country,j.history&&j.history.joined?'desde '+yr(j.history.joined):'']),
};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const dec=s=>s.replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#0?39;|&apos;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/\s+/g,' ').trim();
// Nome/bio públicos lidos das meta tags da página do perfil (og:title / og:description)
function meta(t){const h=t.slice(0,60000),g=p=>{const m=h.match(new RegExp('<meta[^>]+(?:property|name)=["\']'+p+'["\'][^>]*?content=["\']([^"\']*)["\']','i'))||h.match(new RegExp('<meta[^>]+content=["\']([^"\']*)["\'][^>]*?(?:property|name)=["\']'+p+'["\']','i'));return m?dec(m[1]):''};
  const bad=/log ?in|sign ?(up|in)|javascript|cookies|captcha/i;let a=g('og:title')||g('twitter:title'),b=g('og:description')||g('description');
  if(bad.test(a))a='';if(bad.test(b))b='';return jn([a.slice(0,70),b.slice(0,90)]).slice(0,160)}
// lê só o começo da página (mais rápido que baixar tudo)
async function body(r,n=150000){try{const rd=r.body.getReader(),dc=new TextDecoder();let s='';while(s.length<n){const x=await rd.read();if(x.done)break;s+=dc.decode(x.value,{stream:true})}try{rd.cancel()}catch(e){}return s}catch(e){return await r.text()}}
// Instagram e X recusam a página pública para servidores; usam o endpoint de perfil / disponibilidade de nome.
const IGH={'user-agent':'Instagram 275.0.0.27.98 Android (33/13; 420dpi; 1080x2400; samsung; SM-G991B; o1s; exynos2100; pt_BR; 458229237)','x-ig-app-id':'936619743392459','accept':'*/*'};
const SP={
 'Instagram':async u=>{const r=await fetch('https://i.instagram.com/api/v1/users/web_profile_info/?username='+encodeURIComponent(u),{headers:IGH,signal:AbortSignal.timeout(3000)});
  if(r.status===404)return{status:'not_found'};if(r.status!==200)return null;
  let j;try{j=await r.json()}catch(e){return null}
  const d=j&&j.data&&j.data.user;
  if(d)return{status:'found',info:jn([d.full_name,d.is_verified?'verificado':'',d.is_private?'privado':'',d.edge_followed_by?d.edge_followed_by.count+' seguidores':'',d.edge_owner_to_timeline_media?d.edge_owner_to_timeline_media.count+' posts':''])};
  return j&&j.data&&j.data.user===null&&j.status==='ok'?{status:'not_found'}:null},
 'X (Twitter)':async u=>{const r=await fetch('https://api.twitter.com/i/users/username_available.json?username='+encodeURIComponent(u),{headers:{'user-agent':UA,'accept':'application/json'},signal:AbortSignal.timeout(3000)});
  if(r.status!==200)return null;let j;try{j=await r.json()}catch(e){return null}
  return j.reason==='taken'?{status:'found'}:(j.reason==='available'&&j.valid===true?{status:'not_found'}:null)}
};
async function check(s,u,ctx){
  const fill=t=>t.replace(/\{u\}/g,encodeURIComponent(u)).replace(/\{l\}/g,encodeURIComponent(u.toLowerCase()));
  const url=fill(s[2]||s[1]);
  if(RX[s[0]]&&!RX[s[0]].test(u))return{name:s[0],status:'na',url};
  if(SP[s[0]]){let x=null;try{x=await SP[s[0]](u)}catch(e){}return x?{name:s[0],status:x.status,url,info:x.info||''}:{name:s[0],status:'unknown',url}}
  for(let i=0;i<2;i++){
    if(ctx.n>=48)return{name:s[0],status:'unknown',url};
    ctx.n++;
    try{
      const r=await fetch(fill(s[1]),{headers:{'User-Agent':UA,'Accept':'text/html,application/json'},redirect:'follow',signal:AbortSignal.timeout(3000)});
      if(s[6]){
        if(r.status===s[6])return{name:s[0],status:'found',url};
        if(r.status===200)return{name:s[0],status:'not_found',url};
      }else{
        if(r.status===404||r.status===410||r.status===s[5])return{name:s[0],status:'not_found',url};
        if(r.status===200){
          if(s[7])return{name:s[0],status:'unknown',url};
          const t=await body(r),low=t.toLowerCase(),api=!!(s[3]||INFO[s[0]]||s[5]);
          if(r.headers.get('cf-mitigated')||/just a moment|enable javascript and cookies|attention required|captcha|access denied/i.test(t.slice(0,4000))&&!api)return{name:s[0],status:'unknown',url};
          if(s[3]){const nf=s[4]==='eq'?t.trim()===s[3]:t.includes(s[3]);if(nf)return{name:s[0],status:'not_found',url}}
          if(!api){
            // anti falso-positivo: muitos sites respondem 200 para perfis que não existem
            if(r.redirected){
              try{const a=new URL(fill(s[1])),b=new URL(r.url),dom=x=>x.hostname.split('.').slice(-2).join('.');
                if(dom(a)!==dom(b))return{name:s[0],status:'unknown',url};
                const pa=a.pathname.replace(/\/$/,'').toLowerCase(),pb=b.pathname.replace(/\/$/,'').toLowerCase();
                if(pa!==pb)return{name:s[0],status:'not_found',url};
              }catch(e){}
            }
            const ti=((t.match(/<title[^>]*>([\s\S]*?)<\/title>/i)||[])[1]||'').toLowerCase();
            if(/\b404\b|not found|não encontrad|page doesn.t exist|doesn.t exist|does not exist|no such user|user not found|isn.t available|unavailable|couldn.t find|nothing here|page not available|sign up|log in/.test(ti))return{name:s[0],status:'not_found',url};
            if(low.indexOf(u.toLowerCase())<0)return{name:s[0],status:'unknown',url};
          }
          let info='';
          if(INFO[s[0]]){try{info=INFO[s[0]](JSON.parse(t))||''}catch(e){}}else if(!api){try{info=meta(t)}catch(e){}}
          return{name:s[0],status:'found',url,info};
        }
      }
      if(i===0&&(r.status===429||r.status>=500)){await sleep(250);continue}
      return{name:s[0],status:'unknown',url};
    }catch(e){if(i===0&&e&&e.name!=='TimeoutError'&&e.name!=='AbortError'){await sleep(150);continue}return{name:s[0],status:'unknown',url}}
  }
  return{name:s[0],status:'unknown',url};
}
async function hibpRaw(path,env){
  const r=await fetch('https://haveibeenpwned.com/api/v3/'+path,{headers:{'hibp-api-key':env.HIBP_KEY,'user-agent':'OSINT-AV2'},signal:AbortSignal.timeout(6000)});
  if(r.status===404)return{ok:true,data:[]};
  if(r.status===200)return{ok:true,data:await r.json()};
  return{ok:false,status:r.status,retry:r.headers.get('retry-after')};
}
async function xon(e){
  const q=encodeURIComponent(e),o={headers:{'user-agent':'OSINT-AV2'},signal:AbortSignal.timeout(6000)};
  try{
    const an=fetch('https://api.xposedornot.com/v1/breach-analytics?email='+q,{headers:o.headers,signal:AbortSignal.timeout(6000)}).catch(()=>null);
    const r=await fetch('https://api.xposedornot.com/v1/check-email/'+q,o);
    if(r.status===404)return{ok:true,data:[]};
    if(r.status!==200)return{ok:false,status:r.status};
    const j=await r.json(),names=[].concat(...(j.breaches||[])).filter(x=>typeof x==='string'),det={};
    try{
      const a=await an;
      if(a&&a.ok){const aj=await a.json();((aj.ExposedBreaches||{}).breaches_details||[]).forEach(d=>{det[String(d.breach||'').toLowerCase()]=d})}
    }catch(x){}
    return{ok:true,data:names.map(n=>{const d=det[n.toLowerCase()]||{};return{name:n,title:n,domain:d.domain||'',date:d.xposed_date?String(d.xposed_date):'',count:d.xposed_records||0,classes:d.xposed_data?String(d.xposed_data).split(';').map(x=>x.trim()).filter(Boolean):[],verified:true}})};
  }catch(err){return{ok:false}}
}
async function erep(e){
  try{
    const r=await fetch('https://emailrep.io/'+encodeURIComponent(e),{headers:{'user-agent':'OSINT-AV2','accept':'application/json'},signal:AbortSignal.timeout(4000)});
    if(r.status!==200)return null;
    const j=await r.json(),d=j.details||{};
    if(typeof j.reputation!=='string')return null;
    return{reputation:j.reputation,suspicious:!!j.suspicious,references:j.references||0,
      firstSeen:d.first_seen&&d.first_seen!=='never'?d.first_seen:'',lastSeen:d.last_seen&&d.last_seen!=='never'?d.last_seen:'',
      blacklisted:!!d.blacklisted,malicious:!!d.malicious_activity,maliciousRecent:!!d.malicious_activity_recent,
      credentialsLeaked:!!d.credentials_leaked,dataBreach:!!d.data_breach,spam:!!d.spam,disposable:!!d.disposable,freeProvider:!!d.free_provider,
      deliverable:d.deliverable==null?null:!!d.deliverable,acceptAll:d.accept_all==null?null:!!d.accept_all,validMx:d.valid_mx==null?null:!!d.valid_mx,
      domainExists:d.domain_exists==null?null:!!d.domain_exists,domainReputation:d.domain_reputation||'',newDomain:!!d.new_domain,
      domainAgeDays:d.days_since_domain_creation||0,suspiciousTld:!!d.suspicious_tld,spoofable:d.spoofable==null?null:!!d.spoofable,
      profiles:Array.isArray(d.profiles)?d.profiles.filter(x=>typeof x==='string'):[]};
  }catch(err){return null}
}
async function stealer(e){
  try{
    const r=await fetch('https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email='+encodeURIComponent(e),{headers:{'user-agent':'OSINT-AV2','accept':'application/json'},signal:AbortSignal.timeout(6000)});
    if(r.status===404)return{ok:true,stealers:[]};
    if(r.status!==200)return{ok:false,status:r.status};
    const j=await r.json(),sa=v=>Array.isArray(v)?v.filter(x=>typeof x==='string').slice(0,5):[],mk=v=>{v=typeof v==='string'?v:'';return v.indexOf('*')>-1?v:v.slice(0,1)+'*'.repeat(Math.min(Math.max(v.length-1,0),8))},mm=v=>sa(v).map(mk);
    return{ok:true,stealers:(Array.isArray(j.stealers)?j.stealers:[]).slice(0,20).map(x=>({date:x.date_compromised||'',family:x.stealer_family||'',computer:x.computer_name||'',os:x.operating_system||'',ip:mk(x.ip),antiviruses:sa(x.antiviruses),corporate:x.total_corporate_services||0,user:x.total_user_services||0,logins:mm(x.top_logins),passwords:mm(x.top_passwords)}))};
  }catch(err){return{ok:false}}
}
/* Cadastro em serviços: só consultas passivas (checagem de "e-mail já cadastrado"), que NÃO enviam e-mail nem SMS ao dono do endereço.
   Cada item: [nome, link, função]. A função devolve 'found' | 'not_found' | 'unknown'. Só marca found com resposta positiva explícita;
   serviços onde a ausência não é confiável nunca devolvem not_found. Para somar serviços, acrescente itens aqui. */
const AJ={'user-agent':UA,'accept':'application/json'};
const ACCOUNTS=[
 ['Microsoft (Outlook / 365)','https://account.microsoft.com/',async e=>{
   const r=await fetch('https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US',{method:'POST',headers:{...AJ,'content-type':'application/json'},body:JSON.stringify({Username:e,isOtherIdpSupported:true,checkPhones:false,isRemoteNGCSupported:false,isCookieBannerShown:false,isFidoSupported:false,originalRequest:'',country:'US',forceotclogin:false,isExternalFederationDisallowed:false,isRemoteConnectSupported:false,federationFlags:0,isSignup:false,flowToken:'',isAccessPassSupported:false}),signal:AbortSignal.timeout(4500)});
   if(r.status!==200)return'unknown';const v=(await r.json()).IfExistsResult;
   return v===0||v===5||v===6?'found':v===1?'not_found':'unknown'}],
 ['Spotify','https://open.spotify.com/',async e=>{
   const r=await fetch('https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email='+encodeURIComponent(e),{headers:AJ,signal:AbortSignal.timeout(4500)});
   if(r.status!==200)return'unknown';const s=(await r.json()).status;
   return s===20?'found':s===1?'not_found':'unknown'}],
 ['Firefox / Mozilla','https://accounts.firefox.com/',async e=>{
   const r=await fetch('https://api.accounts.firefox.com/v1/account/status',{method:'POST',headers:{...AJ,'content-type':'application/json'},body:JSON.stringify({email:e}),signal:AbortSignal.timeout(4500)});
   if(r.status!==200)return'unknown';const x=(await r.json()).exists;
   return x===true?'found':x===false?'not_found':'unknown'}],
 ['Pinterest','https://www.pinterest.com/',async e=>{
   const d=encodeURIComponent(JSON.stringify({options:{email:e},context:{}}));
   const r=await fetch('https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/?source_url=%2F&data='+d,{headers:{...AJ,'x-requested-with':'XMLHttpRequest'},signal:AbortSignal.timeout(4500)});
   if(r.status!==200)return'unknown';const x=((await r.json()).resource_response||{}).data;
   return x===true?'found':'unknown'}],
 ['Duolingo','https://www.duolingo.com/',async e=>{
   const r=await fetch('https://www.duolingo.com/2017-06-30/users?email='+encodeURIComponent(e),{headers:AJ,signal:AbortSignal.timeout(4500)});
   if(r.status!==200)return'unknown';const u=(await r.json()).users;
   return Array.isArray(u)&&u.length?'found':'unknown'}],
 // Instagram: consulta de "e-mail já em uso" do formulário de cadastro (não envia nada ao dono do e-mail).
 ['Instagram','https://www.instagram.com/',async e=>{
   const pg=await fetch('https://www.instagram.com/accounts/emailsignup/',{headers:{'user-agent':UA,'accept':'text/html'},signal:AbortSignal.timeout(4500)});
   const ck=pg.headers.get('set-cookie')||'',m=ck.match(/csrftoken=([^;]+)/);
   if(!m)return'unknown';
   const r=await fetch('https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/',{method:'POST',headers:{'user-agent':UA,'accept':'*/*','content-type':'application/x-www-form-urlencoded','x-csrftoken':m[1],'x-requested-with':'XMLHttpRequest','x-ig-app-id':'936619743392459','referer':'https://www.instagram.com/accounts/emailsignup/','cookie':'csrftoken='+m[1]},body:'email='+encodeURIComponent(e)+'&username=&first_name=&opt_into_one_tap=false',signal:AbortSignal.timeout(4500)});
   if(r.status!==200)return'unknown';
   let j;try{j=await r.json()}catch(x){return'unknown'}
   const em=j&&j.errors&&j.errors.email;
   if(Array.isArray(em)&&em.some(x=>x&&x.code==='email_is_taken'))return'found';
   if(j&&!j.message&&(j.status==='ok'||j.dryrun_passed!==undefined)&&!em)return'not_found';
   return'unknown'}],
 // X (Twitter): endpoint público de disponibilidade de e-mail usado no cadastro.
 ['X (Twitter)','https://x.com/',async e=>{
   const r=await fetch('https://api.twitter.com/i/users/email_available.json?email='+encodeURIComponent(e),{headers:AJ,signal:AbortSignal.timeout(4500)});
   if(r.status!==200)return'unknown';
   const j=await r.json();
   return j.taken===true?'found':(j.taken===false&&j.valid===true?'not_found':'unknown')}],
 // Facebook, TikTok, Kwai e Threads não oferecem checagem passiva de e-mail (só pelo fluxo de recuperação de senha,
 // que envia mensagem ao dono, ou por APIs assinadas do app). Por isso ficam sempre como "não verificável", nunca "sem cadastro".
 ['Facebook','https://www.facebook.com/',async e=>'unknown'],
 ['TikTok','https://www.tiktok.com/',async e=>'unknown'],
 ['Kwai','https://www.kwai.com/',async e=>'unknown'],
 ['Threads','https://www.threads.net/',async e=>'unknown']
];
async function accounts(e){
  return Promise.all(ACCOUNTS.map(async s=>{
    try{return{name:s[0],status:await s[2](e),url:s[1]}}catch(err){return{name:s[0],status:'unknown',url:s[1]}}
  }));
}

let torCache={t:0,set:null};
async function torList(){
  if(torCache.set&&Date.now()-torCache.t<3600000)return torCache.set;
  try{const r=await fetch('https://check.torproject.org/torbulkexitlist',{headers:{'user-agent':UA},signal:AbortSignal.timeout(4000)});
    if(r.status===200){torCache={t:Date.now(),set:new Set((await r.text()).split('\n').map(x=>x.trim()).filter(Boolean))}}}catch(e){}
  return torCache.set;
}
async function ipIntel(ip){
  const v6=ip.includes(':'),T=n=>AbortSignal.timeout(n),H={headers:{'user-agent':'OSINT-AV2','accept':'application/json'}};
  const jf=async(u,n)=>{try{const r=await fetch(u,{...H,signal:T(n||6000)});return r.status===200?await r.json():null}catch(e){return null}};
  const [geo,gn,otx,pdns,rev,tor]=await Promise.all([
    jf('http://ip-api.com/json/'+encodeURIComponent(ip)+'?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting'),
    jf('https://api.greynoise.io/v3/community/'+encodeURIComponent(ip)),
    jf('https://otx.alienvault.com/api/v1/indicators/'+(v6?'IPv6':'IPv4')+'/'+encodeURIComponent(ip)+'/general'),
    jf('https://otx.alienvault.com/api/v1/indicators/'+(v6?'IPv6':'IPv4')+'/'+encodeURIComponent(ip)+'/passive_dns'),
    (async()=>{try{const r=await fetch('https://api.hackertarget.com/reverseiplookup/?q='+encodeURIComponent(ip),{headers:{'user-agent':UA},signal:T(6000)});if(r.status!==200)return null;const t=await r.text();return /^error|API count|no records/i.test(t.trim())?[]:t.split('\n').map(x=>x.trim().toLowerCase()).filter(x=>/^[a-z0-9.-]+\.[a-z]{2,}$/.test(x))}catch(e){return null}})(),
    torList()
  ]);
  const sources=[];
  const g=geo&&geo.status==='success'?(sources.push('ip-api.com'),{pais:geo.country,codigo:geo.countryCode,regiao:geo.regionName,cidade:geo.city,cep:geo.zip,lat:geo.lat,lon:geo.lon,isp:geo.isp,org:geo.org,asn:(geo.as||'').split(' ')[0],fuso:geo.timezone,hostname:geo.reverse||''}):null;
  const flags=g?{proxy:!!geo.proxy,hosting:!!geo.hosting,mobile:!!geo.mobile}:null;
  let greynoise=null;if(gn&&gn.ip){sources.push('GreyNoise');greynoise={noise:!!gn.noise,riot:!!gn.riot,classification:gn.classification||'',name:gn.name||'',lastSeen:gn.last_seen||''}}
  let o=null;if(otx&&otx.pulse_info){sources.push('AlienVault OTX');o={pulses:otx.pulse_info.count||0}}
  const passiveDns=pdns&&Array.isArray(pdns.passive_dns)?pdns.passive_dns.slice(0,200).map(x=>({host:x.hostname,last:String(x.last||'').slice(0,10)})).filter(x=>x.host):[];
  if(pdns)sources.push('OTX DNS passivo');
  const reverseIp=rev||[];if(rev)sources.push('HackerTarget');
  let torR=null;if(tor){sources.push('Tor Project');torR={exit:tor.has(ip)}}
  return{ip,geo:g,flags,greynoise,otx:o,passiveDns,reverseIp,tor:torR,sources};
}
const BLOCKED='av2company.com.br';
const blocked=v=>{v=String(v||'').toLowerCase().replace(/^.*@/,'').replace(/^www\./,'');return v===BLOCKED||v.endsWith('.'+BLOCKED)};
const norm=s=>String(s||'').toLowerCase().replace(/[^a-z0-9]/g,'');
const core={
  async fetch(req,env){
    const h={'Access-Control-Allow-Origin':ALLOW_ORIGIN,'Access-Control-Allow-Methods':'GET,OPTIONS','Content-Type':'application/json; charset=utf-8','Cache-Control':'public, max-age=300'};
    const J=(o,st)=>{if(st>=400)h['Cache-Control']='no-store';return new Response(JSON.stringify(o),{status:st||200,headers:h})};
    if(req.method==='OPTIONS')return new Response(null,{status:204,headers:h});
    const url=new URL(req.url);
    if(blocked(url.searchParams.get('d'))||blocked(url.searchParams.get('e'))||blocked(url.searchParams.get('u')))return J({error:'pesquisa bloqueada para este alvo'},403);
    if(url.pathname==='/username'){
      const u=(url.searchParams.get('u')||'').trim();
      if(!/^[a-zA-Z0-9._-]{2,40}$/.test(u))return J({error:'username inválido'},400);
      const ctx={n:0},kk=+url.searchParams.get('k'),nn=+url.searchParams.get('n');
      const list=nn>1&&kk>=0&&kk<nn?SITES.filter((_,ix)=>ix%nn===kk):SITES;
      const results=(await Promise.all(list.map(s=>check(s,u,ctx)))).map(r=>({...r,cat:CATOF[r.name]||'Outros'}));
      if(results.some(r=>r.status==='unknown'))h['Cache-Control']='no-store';
      return J({username:u,results});
    }
    if(url.pathname==='/email'){
      h['Cache-Control']='no-store';
      const e=(url.searchParams.get('e')||'').trim().toLowerCase();
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)||e.length>254)return J({error:'e-mail inválido'},400);
      const q=encodeURIComponent(e),useH=!!(env&&env.HIBP_KEY);
      try{
        const [x,b,p,rep]=await Promise.all([xon(e),useH?hibp('breachedaccount/'+q+'?truncateResponse=false&includeUnverified=true',env):Promise.resolve(null),useH?hibp('pasteaccount/'+q,env):Promise.resolve(null),erep(e)]);
        const sources=[];let breaches=[];
        if(b&&b.ok){sources.push('Have I Been Pwned');breaches=b.data.map(y=>({name:y.Name,title:y.Title,domain:y.Domain,date:y.BreachDate,count:y.PwnCount,classes:y.DataClasses||[],verified:y.IsVerified}))}
        if(x.ok){sources.push('XposedOrNot');const seen=new Set(breaches.flatMap(y=>[norm(y.name),norm(y.title),norm(y.domain)]));x.data.forEach(y=>{if(!seen.has(norm(y.name))&&!(y.domain&&seen.has(norm(y.domain))))breaches.push(y)})}
        if(!sources.length){const st=b&&!b.ok?b.status:0;return J({error:st===429?'limite de consultas do HIBP atingido, tente em '+((b&&b.retry)||'alguns')+' s':st===401?'chave HIBP inválida':'as fontes de vazamento não responderam'},502)}
        breaches.sort((m,n)=>String(n.date).localeCompare(String(m.date)));
        const pastes=p&&p.ok?p.data.map(y=>({source:y.Source,title:y.Title,date:y.Date})):[];
        return J({email:e,breached:breaches.length>0,breaches,pastes,sources,rep});
      }catch(err){return J({error:'falha ao consultar vazamentos'},502)}
    }
    if(url.pathname==='/stealer'){
      h['Cache-Control']='no-store';
      const e=(url.searchParams.get('e')||'').trim().toLowerCase();
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)||e.length>254)return J({error:'e-mail inválido'},400);
      const s=await stealer(e);
      if(!s.ok)return J({error:s.status===429?'limite de consultas do Hudson Rock atingido, tente de novo em instantes':'a fonte de infostealers não respondeu'},502);
      return J({email:e,found:s.stealers.length>0,stealers:s.stealers,source:'Hudson Rock (Cavalier)'});
    }
    if(url.pathname==='/accounts'){
      h['Cache-Control']='no-store';
      const e=(url.searchParams.get('e')||'').trim().toLowerCase();
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)||e.length>254)return J({error:'e-mail inválido'},400);
      return J({email:e,results:await accounts(e)});
    }
    if(url.pathname==='/phone'){
      h['Cache-Control']='no-store';
      const n=(url.searchParams.get('n')||'').replace(/\D/g,'');
      if(!/^\d{10,15}$/.test(n))return J({error:'número inválido'},400);
      if(!(env&&env.VERIPHONE_KEY))return J({number:'+'+n,configured:false});
      try{
        const r=await fetch('https://api.veriphone.io/v2/verify?phone='+encodeURIComponent('+'+n)+'&key='+encodeURIComponent(env.VERIPHONE_KEY),{headers:{'user-agent':'OSINT-AV2','accept':'application/json'},signal:AbortSignal.timeout(6000)});
        if(r.status===429)return J({error:'limite de consultas da fonte de operadora atingido'},502);
        if(r.status===401||r.status===403)return J({error:'chave da fonte de operadora inválida'},502);
        if(r.status!==200)throw new Error('HTTP '+r.status);
        const j=await r.json();
        if(j.status!=='success')return J({error:'a fonte de operadora recusou a consulta'},502);
        return J({number:j.e164||'+'+n,configured:true,valid:!!j.phone_valid,carrier:j.carrier||'',type:j.phone_type||'',country:j.country||'',countryCode:j.country_code||'',region:j.phone_region||'',source:'Veriphone'});
      }catch(err){return J({error:'a fonte de operadora não respondeu'},502)}
    }
    if(url.pathname==='/ip'){
      const i=(url.searchParams.get('i')||'').trim().toLowerCase();
      if(i.length>45||!/^[0-9a-f:.]+$/.test(i)||(!/^\d{1,3}(\.\d{1,3}){3}$/.test(i)&&!/^[0-9a-f:]*:[0-9a-f:]*$/.test(i)))return J({error:'IP inválido'},400);
      try{return J(await ipIntel(i))}catch(err){return J({error:'falha ao consultar o IP'},502)}
    }
    if(url.pathname==='/domain'){
      // Subdomínios e certificados emitidos (Certificate Transparency, via crt.sh). Fonte pública.
      const d=(url.searchParams.get('d')||'').trim().toLowerCase();
      if(!/^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d))return J({error:'domínio inválido'},400);
      try{
        const fin=(src,pairs)=>{
          const subs=new Set();let first='',last='';
          pairs.forEach(([names,nb])=>{names.forEach(n=>{n=String(n).trim().toLowerCase().replace(/^\*\./,'');if(n&&(n===d||n.endsWith('.'+d)))subs.add(n)});const s=String(nb||'').slice(0,10);if(s){if(!first||s<first)first=s;if(!last||s>last)last=s}});
          return{domain:d,total:pairs.length,subdomains:[...subs].sort().slice(0,300),totalSubdomains:subs.size,first,last,source:src};
        };
        const viaCrt=async()=>{const r=await fetch('https://crt.sh/?q=%25.'+encodeURIComponent(d)+'&output=json',{headers:{'user-agent':UA},signal:AbortSignal.timeout(12000)});if(r.status!==200)throw new Error('crt.sh '+r.status);const rows=await r.json();return fin('crt.sh',rows.map(x=>[String(x.name_value||'').split('\n'),x.not_before]))};
        const viaCs=async()=>{const r=await fetch('https://api.certspotter.com/v1/issuances?domain='+encodeURIComponent(d)+'&include_subdomains=true&expand=dns_names',{headers:{'user-agent':UA,'accept':'application/json'},signal:AbortSignal.timeout(9000)});if(r.status!==200)throw new Error('certspotter '+r.status);const rows=await r.json();if(!Array.isArray(rows))throw new Error('certspotter');return fin('CertSpotter',rows.map(x=>[x.dns_names||[],x.not_before]))};
        return J(await Promise.any([viaCrt(),viaCs()]));
      }catch(err){return J({error:'a fonte de certificados não respondeu'},502)}
    }
    return J({error:'use /ip?i=1.2.3.4 ou /domain?d=site.com ou /username?u=nome ou /email?e=endereco ou /stealer?e=endereco ou /accounts?e=endereco ou /phone?n=numero'},404);
  }
};

const rawFetch=globalThis.fetch.bind(globalThis);
const HEALTH={'api.xposedornot.com':'XposedOrNot','haveibeenpwned.com':'Have I Been Pwned','api.veriphone.io':'Veriphone','cavalier.hudsonrock.com':'Hudson Rock','ip-api.com':'ip-api','api.greynoise.io':'GreyNoise','otx.alienvault.com':'AlienVault OTX','api.hackertarget.com':'HackerTarget','crt.sh':'crt.sh','api.certspotter.com':'CertSpotter','emailrep.io':'EmailRep','check.torproject.org':'Tor Project','login.microsoftonline.com':'Microsoft','spclient.wg.spotify.com':'Spotify','api.accounts.firefox.com':'Firefox','i.instagram.com':'Instagram','api.twitter.com':'X'};
const SRC={},FAILS=[];
const ROUTES={'/username':{w:3,heavy:1},'/email':{w:3,heavy:1},'/accounts':{w:3,heavy:1},'/stealer':{w:1,heavy:1},'/phone':{w:2},'/ip':{w:2,heavy:1,ttl:1800},'/domain':{w:2,heavy:1,ttl:3600},'/status':{w:0}};
const RLM=new Map(),PERIP=new Map(),INF=new Map(),NEG=new Map();let ACTIVE=0;

function log(lv,ev,o){try{console[lv==='warn'?'warn':lv==='error'?'error':'log'](JSON.stringify({t:new Date().toISOString(),ev,...o}))}catch(e){}}
// fetch com medição por fonte + disjuntor: 4 falhas seguidas pausam a fonte por 30 s (as outras seguem normalmente)
async function fetch(input,init){
  let host='';try{host=new URL(typeof input==='string'?input:input.url).hostname}catch(e){}
  const name=HEALTH[host];if(!name)return rawFetch(input,init);
  const s=SRC[name]||(SRC[name]={ok:0,fail:0,streak:0,openUntil:0,ms:0,lastFail:''});
  if(s.openUntil>Date.now())throw new Error('fonte pausada: '+name);
  const t0=Date.now();
  try{const r=await rawFetch(input,init);mark(s,name,!(r.status===429||r.status>=500),'HTTP '+r.status,Date.now()-t0);return r}
  catch(e){mark(s,name,false,e&&e.name==='TimeoutError'?'timeout':String(e&&e.message||e),Date.now()-t0);throw e}
}
function mark(s,name,ok,why,ms){
  s.ms=Math.round(s.ms*.7+ms*.3);
  if(ok){s.ok++;s.streak=0;return}
  why=String(why).replace(/key=[^&\s"']+/gi,'key=***').slice(0,80);
  s.fail++;s.streak++;s.lastFail=why;if(s.streak>=4){s.openUntil=Date.now()+30000;s.streak=0}
  FAILS.push({t:new Date().toISOString(),fonte:name,motivo:why});if(FAILS.length>40)FAILS.shift();
  log('warn','falha_fonte',{fonte:name,motivo:why,ms});
}
async function hibp(path,env){try{return await hibpRaw(path,env)}catch(e){return{ok:false,status:0}}} // falha do HIBP não derruba mais o resultado do XposedOrNot

const origins=env=>String(env&&env.ALLOWED_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean);
function cors(origin,allow,rid){return{'Access-Control-Allow-Origin':allow.length?(allow.includes(origin)?origin:'null'):'*','Access-Control-Allow-Methods':'GET,OPTIONS','Access-Control-Max-Age':'86400','Vary':'Origin','X-Request-Id':rid,'X-Content-Type-Options':'nosniff'}}
const ipTag=ip=>ip.includes(':')?ip.split(':').slice(0,3).join(':')+'::':ip.split('.').slice(0,3).join('.')+'.x';

async function limited(env,ip,route,w){
  const lim=+(env&&env.RL_POINTS)||120,now=Date.now();
  if(RLM.size>5000){for(const [k,v] of RLM)if(v.r<now)RLM.delete(k);if(RLM.size>20000)RLM.clear()}
  let e=RLM.get(ip);if(!e||e.r<now){e={r:now+60000,p:0};RLM.set(ip,e)}
  e.p+=w;if(e.p>lim)return Math.max(1,Math.ceil((e.r-now)/1000));
  if(env&&env.RATE_LIMITER){try{const x=await env.RATE_LIMITER.limit({key:ip+route});if(!x.success)return 30}catch(err){}}
  return 0;
}
function acquire(env,ip,rc){if(!rc.heavy)return true;const max=+(env&&env.MAX_CONCURRENT)||16,n=PERIP.get(ip)||0;if(ACTIVE>=max||n>=6)return false;ACTIVE++;PERIP.set(ip,n+1);return true}
function release(ip,rc){if(!rc.heavy)return;ACTIVE=Math.max(0,ACTIVE-1);const n=(PERIP.get(ip)||1)-1;n>0?PERIP.set(ip,n):PERIP.delete(ip)}
const coalesce=(k,fn)=>{let p=INF.get(k);if(!p){p=fn().finally(()=>INF.delete(k));INF.set(k,p)}return p};
async function cacheGet(ck){try{const m=await caches.default.match(ck);return m?{s:m.status,t:await m.text(),cc:'public, max-age=300'}:null}catch(e){return null}}
function cachePut(ctx,ck,r,ttl){try{ctx.waitUntil(caches.default.put(ck,new Response(r.t,{status:r.s,headers:{'Content-Type':'application/json','Cache-Control':'public, max-age='+ttl}})))}catch(e){}}
function ttlFor(route,rc,r){
  if(r.s!==200)return 0;let j;try{j=JSON.parse(r.t)}catch(e){return 0}
  if(route==='/ip'||route==='/domain')return rc.ttl;
  if(route==='/username')return(j.results||[]).some(x=>x.status==='unknown')?0:600;  // só guarda resultado completo
  if(route==='/phone')return j.configured&&j.valid!==undefined?86400:0;              // poupa a cota da Veriphone
  return 0; // e-mail, stealer e accounts nunca ficam em cache (dados pessoais)
}
async function run(req,env,ctx){
  const res=await Promise.race([core.fetch(req,env,ctx),new Promise(r=>setTimeout(()=>r(null),25000))]);
  if(!res)return{s:504,t:JSON.stringify({error:'tempo esgotado ao consultar as fontes'}),cc:'no-store'};
  return{s:res.status,t:await res.text(),cc:res.headers.get('Cache-Control')||'no-store'};
}
export default{
  async fetch(req,env,ctx){
    const rid=crypto.randomUUID().slice(0,8),t0=Date.now(),url=new URL(req.url),route=url.pathname,rc=ROUTES[route];
    const origin=req.headers.get('Origin')||'',allow=origins(env),ip=req.headers.get('CF-Connecting-IP')||'0.0.0.0';
    const H=cors(origin,allow,rid);
    const out=(o,st,x)=>new Response(JSON.stringify(o),{status:st,headers:{...H,'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...x}});
    let cache='MISS',st=0;
    try{
      if(req.method==='OPTIONS')return allow.length&&!allow.includes(origin)?out({error:'origem não permitida'},403):new Response(null,{status:204,headers:H});
      if(req.method!=='GET')return out({error:'método não permitido'},405,{Allow:'GET,OPTIONS'});
      if(req.url.length>600)return out({error:'requisição muito longa'},414);
      if(!rc)return out({error:'rota não encontrada'},404);
      if(allow.length&&!allow.includes(origin))return out({error:'origem não permitida'},403);
      if(route==='/status'){
        const tok=env&&env.STATUS_TOKEN&&(req.headers.get('x-status-token')===env.STATUS_TOKEN||url.searchParams.get('t')===env.STATUS_TOKEN),src={};
        for(const k in SRC){const s=SRC[k];src[k]={ok:s.ok,falhas:s.fail,msMedio:s.ms,pausada:s.openUntil>Date.now(),ultimaFalha:s.lastFail}}
        const o={ok:true,hora:new Date().toISOString(),fontes:src,emAndamento:ACTIVE,observacao:'Contadores por instância do Worker; zeram quando ela reinicia.'};
        if(tok){o.chaves={HIBP_KEY:!!env.HIBP_KEY,VERIPHONE_KEY:!!env.VERIPHONE_KEY};o.config={origensRestritas:allow.length>0,rateLimiter:!!env.RATE_LIMITER};o.falhasRecentes=FAILS.slice(-20)}
        return out(o,200);
      }
      const wait=await limited(env,ip,route,rc.w);
      if(wait)return st=429,out({error:'muitas consultas seguidas, aguarde '+wait+' s'},429,{'Retry-After':String(wait)});
      const key=route+url.search,ck=new Request('https://cache.av2.internal'+key);
      let r=await cacheGet(ck);if(r)cache='HIT';
      if(!r){const n=NEG.get(key);if(n&&n.until>Date.now()){r=n.r;cache='NEG'}}
      if(!r){
        if(!acquire(env,ip,rc))return st=503,out({error:'serviço ocupado, tente de novo em instantes'},503,{'Retry-After':'3'});
        try{r=await coalesce(key,()=>run(req,env,ctx))}finally{release(ip,rc)}
        const ttl=ttlFor(route,rc,r);if(ttl)cachePut(ctx,ck,r,ttl);
        if(r.s>=502){NEG.set(key,{r,until:Date.now()+15000});if(NEG.size>500)NEG.clear();log('warn','falha_rota',{rid,rota:route,status:r.s})}
      }
      st=r.s;
      return new Response(r.t,{status:r.s,headers:{...H,'Content-Type':'application/json; charset=utf-8','Cache-Control':r.s===200?r.cc:'no-store','X-Cache':cache}});
    }catch(err){
      st=500;log('error','erro_interno',{rid,rota:route,motivo:String(err&&err.message||err).replace(/key=[^&\s"']+/gi,'key=***').slice(0,120)});
      return out({error:'erro interno, tente novamente',id:rid},500);
    }finally{
      // o log nunca guarda o alvo pesquisado (e-mail, telefone, usuário), só rota, status, tempo e prefixo do IP
      if(rc&&route!=='/status')log('log','req',{rid,rota:route,status:st,ms:Date.now()-t0,cache,ip:ipTag(ip)});
    }
  }
};
