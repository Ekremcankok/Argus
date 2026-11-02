// İç Ağ Recon Paneli — çok görünümlü SPA (bağımlılıksız)
const SEV = ['critical','high','medium','low','info'];
const SEV_TR = {critical:'Kritik',high:'Yüksek',medium:'Orta',low:'Düşük',info:'Bilgi'};
const SEV_COLOR = {critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22d3ee',info:'#8fa0b3'};
const CAT_TR = {vuln:'Zafiyet',config:'Yapılandırma',cred:'Kimlik Bilgisi',service:'Servis',info:'Bilgi'};

const S = { modules:[], catalog:[], catById:{}, job:null, status:'idle' };

const $ = s => document.querySelector(s);
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function get(u){ const r=await fetch(u); if(!r.ok) throw new Error((await r.json().catch(()=>({}))).detail||r.status); return r.json(); }
async function post(u,b){ const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});
  if(!r.ok) throw new Error((await r.json().catch(()=>({}))).detail||r.status); return r.json(); }
const fmtTime = ts => ts? new Date(ts*1000).toLocaleString('tr-TR',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}) : '—';
const sevBadge = s => `<span class="sev sev-${s}">${SEV_TR[s]||s}</span>`;
const stBadge = s => `<span class="st st-${s}">${s}</span>`;

function miniBars(counts){
  return `<span class="minibars">`+SEV.map(s=>{const n=counts[s]||0; if(!n)return '';
    const h=Math.min(18,6+n*2); return `<i class="bg-${s}" style="height:${h}px" title="${SEV_TR[s]}: ${n}"></i>`;}).join('')+`</span>`;
}

function donut(counts,total){
  const r=52,c=2*Math.PI*r; let off=0; const segs=[];
  SEV.forEach(s=>{const n=counts[s]||0; if(!n||!total)return; const frac=n/total; const len=frac*c;
    segs.push(`<circle r="${r}" cx="70" cy="70" fill="none" stroke="${SEV_COLOR[s]}" stroke-width="18"
      stroke-dasharray="${len} ${c-len}" stroke-dashoffset="${-off}" transform="rotate(-90 70 70)"/>`); off+=len;});
  if(!segs.length) segs.push(`<circle r="${r}" cx="70" cy="70" fill="none" stroke="#1b2535" stroke-width="18"/>`);
  return `<svg width="140" height="140" viewBox="0 0 140 140">${segs.join('')}
    <text x="70" y="64" text-anchor="middle" fill="#dbe4ee" font-size="26" font-weight="800">${total}</text>
    <text x="70" y="84" text-anchor="middle" fill="#7f8ea1" font-size="11">bulgu</text></svg>`;
}

// ── router ──
const routes = [
  [/^#\/?$/, viewDashboard],
  [/^#\/scans$/, viewScans],
  [/^#\/scans\/(.+)$/, viewScanDetail],
  [/^#\/hosts$/, viewHosts],
  [/^#\/host\/(.+)$/, viewHostDetail],
  [/^#\/findings$/, viewFindings],
  [/^#\/finding\/(.+)$/, viewFindingDetail],
  [/^#\/catalog$/, viewCatalog],
  [/^#\/catalog\/(.+)$/, viewCatalogDetail],
  [/^#\/new$/, viewNew],
];
function router(){
  const h=location.hash||'#/';
  for(const [re,fn] of routes){ const m=h.match(re); if(m){ setActiveNav(h); fn(...m.slice(1)); return; } }
  viewDashboard();
}
function setActiveNav(h){
  document.querySelectorAll('.nav a').forEach(a=>{
    const base='#/'+(h.split('/')[1]||'');
    a.classList.toggle('active', a.getAttribute('href')===base || (base==='#/'&&a.getAttribute('href')==='#/'));
  });
}
function setTop(title,crumb){ $('#ttl').textContent=title; $('#crumb').innerHTML=crumb?`<span class="crumb">${crumb}</span>`:''; }
const C = () => $('#content');

// ── Dashboard ──
async function viewDashboard(){
  setTop('Genel Bakış','');
  const d=await get('/api/dashboard');
  if(d.status==='idle'){ C().innerHTML=`<div class="card"><div class="empty">Henüz tarama yok.<br><br>
    <button class="primary" onclick="location.hash='#/new'">+ İlk taramayı başlat</button></div></div>`; return; }
  const sc=d.severity_counts||{};
  const tiles=[['critical','Kritik'],['high','Yüksek'],['medium','Orta'],['low','Düşük'],['info','Bilgi']]
    .map(([k,l])=>`<div class="tile c-${k}"><div class="bar"></div><div class="n">${sc[k]||0}</div><div class="l">${l}</div></div>`).join('')
    +`<div class="tile c-accent"><div class="bar"></div><div class="n">${d.hosts}</div><div class="l">Host</div></div>`
    +`<div class="tile c-high"><div class="bar"></div><div class="n">${d.manual}</div><div class="l">Manuel aksiyon</div></div>`;
  const legend=SEV.map(s=>`<div class="li"><span class="dot-sev bg-${s}"></span>
    <span class="k">${SEV_TR[s]}</span><span class="v">${sc[s]||0}</span></div>`).join('');
  const cats=Object.entries(d.by_category||{}).sort((a,b)=>b[1]-a[1]);
  const maxc=Math.max(1,...cats.map(x=>x[1]));
  const catbars=cats.length?cats.map(([k,v])=>`<div class="catbar"><div class="top"><span>${CAT_TR[k]||k}</span><span class="muted">${v}</span></div>
    <div class="track"><div class="fill" style="width:${v/maxc*100}%"></div></div></div>`).join(''):'<div class="muted">—</div>';
  const prog=S.modules.map(m=>{const st=d.module_status[m.name]||{}; const s=st.status||'pending';
    return `<div class="prow"><span class="pdot ${s}"></span><span class="pn">${m.label||m.name}</span>
      <span class="pm">${s}${st.message?' · '+esc(st.message):''}</span></div>`;}).join('');
  const top=(d.top||[]).map(f=>`<tr class="clk" onclick="location.hash='#/finding/${encodeURIComponent(f.id)}'">
    <td>${sevBadge(f.severity)}</td><td>${esc(f.title)}${f.manual_followup?' <span class="chip manual">MANUEL</span>':''}</td>
    <td class="mono">${esc(f.host)}</td></tr>`).join('')||`<tr><td colspan="3" class="muted">Bulgu yok.</td></tr>`;

  C().innerHTML=`
    <div class="row" style="justify-content:space-between;align-items:center;margin-bottom:16px">
      <div><span class="st st-${d.status}">${d.status}</span>
        <span class="muted" style="margin-left:10px">${esc(d.name)} · ${d.mode}${d.dry_run?' · dry-run':''}</span></div>
      <div class="muted">${fmtTime(d.started_at)}</div>
    </div>
    <div class="tiles" style="margin-bottom:16px">${tiles}</div>
    <div class="grid" style="grid-template-columns:1fr 1fr">
      <div class="card"><h2>Önem dağılımı</h2><div class="donut-wrap">${donut(sc,d.total)}<div class="legend">${legend}</div></div></div>
      <div class="card"><h2>Kategoriye göre</h2><div class="catbars">${catbars}</div></div>
    </div>
    <div class="grid" style="grid-template-columns:1fr 1fr;margin-top:16px">
      <div class="card"><h2>Faz ilerlemesi</h2><div class="plist">${prog}</div></div>
      <div class="card"><h2>Öncelikli bulgular</h2><table><tbody>${top}</tbody></table></div>
    </div>`;
}

// ── Scans ──
async function viewScans(){
  setTop('Taramalar','');
  const scans=await get('/api/scans');
  if(!scans.length){ C().innerHTML=`<div class="card"><div class="empty">Henüz tarama yok.<br><br>
    <button class="primary" onclick="location.hash='#/new'">+ Yeni tarama</button></div></div>`; return; }
  const rows=scans.map(s=>`<tr class="clk" onclick="location.hash='#/scans/${s.id}'">
    <td><b>${esc(s.name)}</b><div class="muted mono" style="font-size:12px">${esc((s.include||[]).join(', '))}</div></td>
    <td>${stBadge(s.status)}</td><td>${s.mode}${s.dry_run?' <span class="chip">dry</span>':''}</td>
    <td class="num">${s.hosts}</td><td class="num">${s.total}</td><td>${miniBars(s.severity_counts)}</td>
    <td class="muted">${fmtTime(s.started_at)}</td></tr>`).join('');
  C().innerHTML=`<div class="card" style="padding:4px 4px 0"><table>
    <thead><tr><th>Tarama</th><th>Durum</th><th>Mod</th><th>Host</th><th>Bulgu</th><th>Önem</th><th>Başlangıç</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

async function viewScanDetail(id){
  setTop('Tarama detayı',`<a href="#/scans">Taramalar</a> / ${id}`);
  const d=await get('/api/scans/'+id);
  const prog=S.modules.map(m=>{const st=d.module_status[m.name]||{}; const s=st.status||'pending';
    return `<div class="prow"><span class="pdot ${s}"></span><span class="pn">${m.label||m.name}</span>
      <span class="pm">${s}${st.message?' · '+esc(st.message):''}</span></div>`;}).join('');
  const ev=(d.events||[]).map(e=>`<div class="e-${e.status}">${fmtTime(e.ts).split(' ').pop()}  ${e.module}  [${e.status}]  ${esc(e.message||'')}</div>`).join('');
  C().innerHTML=`
    <div class="row" style="justify-content:space-between;margin-bottom:16px">
      <div><span class="st st-${d.status}">${d.status}</span>
        <span class="muted" style="margin-left:10px">${esc(d.name)} · ${d.mode}${d.dry_run?' · dry-run':''}</span>
        ${d.status==='running'?'<button class="danger" style="margin-left:12px" onclick="stopScan()">■ Durdur</button>':''}</div>
      <div class="row">
        <button onclick="location.hash='#/findings'">Bulgular (${d.total})</button>
        <button onclick="location.hash='#/hosts'">Hostlar (${d.hosts})</button></div>
    </div>
    <div class="kv card" style="margin-bottom:16px">
      <span class="k">Kapsam</span><span class="mono">${esc((d.include||[]).join(', '))}</span>
      <span class="k">Hariç</span><span class="mono">${esc((d.exclude||[]).join(', '))||'—'}</span>
      <span class="k">Koşu dizini</span><span class="mono">${esc(d.run_dir)}</span>
      <span class="k">Başlangıç</span><span>${fmtTime(d.started_at)}</span>
      ${d.error?`<span class="k">Hata</span><span style="color:var(--fail)">${esc(d.error)}</span>`:''}
    </div>
    <div class="grid" style="grid-template-columns:1fr 1fr">
      <div class="card"><h2>Faz ilerlemesi</h2><div class="plist">${prog}</div></div>
      <div class="card"><h2>Olay akışı</h2><div class="log">${ev||'<span class="muted">—</span>'}</div></div>
    </div>`;
}
window.stopScan=async()=>{ await post('/api/stop'); };

// ── Hosts ──
async function viewHosts(){
  setTop('Hostlar','');
  const inv=await get('/api/hosts');
  const hosts=inv.hosts||{};
  const keys=Object.keys(hosts);
  if(!keys.length){ C().innerHTML=`<div class="card"><div class="empty">Host envanteri boş. Önce bir tarama çalıştırın.</div></div>`; return; }
  const rows=keys.map(ip=>{const h=hosts[ip];
    const roles=(h.roles||[]).map(r=>`<span class="chip role">${r}</span>`).join(' ');
    return `<tr class="clk" onclick="location.hash='#/host/${encodeURIComponent(ip)}'">
      <td class="mono"><b>${esc(ip)}</b></td><td>${esc(h.hostname||'')}</td>
      <td class="muted">${esc(h.os||'—')}</td><td>${roles||'<span class="muted">—</span>'}</td>
      <td class="num">${(h.ports||[]).length}</td>
      <td>${h.smb_signing===false?'<span class="chip manual">signing yok</span>':(h.smb_signing===true?'<span class="chip">imzalı</span>':'<span class="muted">—</span>')}</td>
      <td class="num">${h.finding_count||0}</td></tr>`;}).join('');
  C().innerHTML=`<div class="card" style="padding:4px 4px 0"><table>
    <thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Roller</th><th>Port</th><th>SMB</th><th>Bulgu</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

async function viewHostDetail(ip){
  ip=decodeURIComponent(ip);
  setTop('Host: '+ip,`<a href="#/hosts">Hostlar</a> / ${ip}`);
  const [inv,finds]=await Promise.all([get('/api/hosts'),get('/api/findings')]);
  const h=(inv.hosts||{})[ip]||{};
  const svcRows=Object.entries(h.services||{}).sort((a,b)=>a[0]-b[0]).map(([p,s])=>`<tr>
    <td class="mono">${p}</td><td>${esc(s.name||'')}</td><td class="muted">${esc([s.product,s.version].filter(Boolean).join(' '))||'—'}</td></tr>`).join('')
    ||'<tr><td colspan="3" class="muted">Servis bilgisi yok.</td></tr>';
  const hf=finds.filter(f=>f.host===ip).map(f=>`<tr class="clk" onclick="location.hash='#/finding/${encodeURIComponent(f.id)}'">
    <td>${sevBadge(f.severity)}</td><td>${esc(f.title)}</td><td class="mono">${f.port||''}</td>
    <td><span class="chip">${f.confidence}</span></td></tr>`).join('')
    ||'<tr><td colspan="4" class="muted">Bu host için bulgu yok.</td></tr>';
  C().innerHTML=`<div class="backlink" onclick="location.hash='#/hosts'">← Hostlar</div>
    <div class="kv card" style="margin-bottom:16px">
      <span class="k">IP</span><span class="mono">${esc(ip)}</span>
      <span class="k">Hostname</span><span>${esc(h.hostname||'—')}</span>
      <span class="k">OS</span><span>${esc(h.os||'—')}</span>
      <span class="k">Roller</span><span>${(h.roles||[]).map(r=>`<span class="chip role">${r}</span>`).join(' ')||'—'}</span>
      <span class="k">SMB signing</span><span>${h.smb_signing===false?'kapalı (relay hedefi)':(h.smb_signing===true?'zorunlu':'—')}</span>
    </div>
    <div class="grid" style="grid-template-columns:1fr 1fr">
      <div class="card"><h2>Açık servisler</h2><table><thead><tr><th>Port</th><th>Servis</th><th>Sürüm</th></tr></thead><tbody>${svcRows}</tbody></table></div>
      <div class="card"><h2>Bulgular</h2><table><tbody>${hf}</tbody></table></div>
    </div>`;
}

// ── Findings ──
let _ffilter={sev:'all',q:''};
async function viewFindings(){
  setTop('Bulgular','');
  const finds=await get('/api/findings');
  const render=()=>{
    const f=finds.filter(x=>(_ffilter.sev==='all'||x.severity===_ffilter.sev)
      &&(!_ffilter.q||(x.title+x.host+(x.source_tool||'')).toLowerCase().includes(_ffilter.q.toLowerCase())));
    const rows=f.map(x=>`<tr class="clk" onclick="location.hash='#/finding/${encodeURIComponent(x.id)}'">
      <td>${sevBadge(x.severity)}</td><td>${esc(x.title)}${x.manual_followup?' <span class="chip manual">MANUEL</span>':''}</td>
      <td class="mono">${esc(x.host)}</td><td class="mono">${x.port||''}</td>
      <td><span class="chip">${x.confidence}</span></td><td><span class="chip">${x.exploitable}</span></td>
      <td class="muted">${esc(x.source_tool||'')}</td></tr>`).join('')
      ||`<tr><td colspan="7" class="empty">Eşleşen bulgu yok.</td></tr>`;
    $('#ftable').innerHTML=rows;
    $('#fcount').textContent=f.length;
  };
  const chips=['all',...SEV].map(s=>`<span class="fchip ${_ffilter.sev===s?'on':''}" data-sev="${s}">${s==='all'?'Tümü':SEV_TR[s]}</span>`).join('');
  C().innerHTML=`<div class="filters">${chips}
    <input class="search" id="fsearch" type="text" placeholder="Ara: başlık, host, araç…" value="${esc(_ffilter.q)}">
    <span class="right muted"><b id="fcount">0</b> bulgu</span></div>
    <div class="card" style="padding:4px 4px 0"><table>
      <thead><tr><th>Önem</th><th>Başlık</th><th>Host</th><th>Port</th><th>Güven</th><th>Sömürü</th><th>Araç</th></tr></thead>
      <tbody id="ftable"></tbody></table></div>`;
  document.querySelectorAll('.fchip').forEach(c=>c.onclick=()=>{_ffilter.sev=c.dataset.sev;
    document.querySelectorAll('.fchip').forEach(x=>x.classList.toggle('on',x===c));render();});
  $('#fsearch').oninput=e=>{_ffilter.q=e.target.value;render();};
  render();
}

async function viewFindingDetail(id){
  id=decodeURIComponent(id);
  setTop('Bulgu detayı',`<a href="#/findings">Bulgular</a>`);
  const finds=await get('/api/findings');
  const f=finds.find(x=>x.id===id);
  if(!f){ C().innerHTML='<div class="card"><div class="empty">Bulgu bulunamadı.</div></div>'; return; }
  let kb=null; if(f.kb_id){ try{ kb=await get('/api/catalog/'+f.kb_id);}catch(e){} }
  C().innerHTML=`<div class="backlink" onclick="location.hash='#/findings'">← Bulgular</div>
    <div class="card" style="margin-bottom:16px">
      <div class="kb-head">${sevBadge(f.severity)}<h1 style="margin:0;font-size:20px">${esc(f.title)}</h1></div>
      <div class="kv" style="margin-top:12px">
        <span class="k">Host</span><span class="mono">${esc(f.host)}${f.port?':'+f.port:''}</span>
        <span class="k">Faz</span><span>${esc(f.phase)}</span>
        <span class="k">Kategori</span><span>${CAT_TR[f.category]||f.category}</span>
        <span class="k">Güven</span><span>${f.confidence}</span>
        <span class="k">Sömürülebilir</span><span>${f.exploitable}${f.manual_followup?' <span class="chip manual">MANUEL DOĞRULA</span>':''}</span>
        <span class="k">Kaynak araç</span><span>${esc(f.source_tool||'—')}</span>
        <span class="k">Kanıt</span><span class="mono" style="font-size:12px">${esc(f.evidence_path||'—')}</span>
        ${f.notes?`<span class="k">Not</span><span>${esc(f.notes)}</span>`:''}
      </div>
    </div>
    ${kb?kbCard(kb):'<div class="card muted">Bu bulgu için katalog kaydı yok.</div>'}`;
}

// ── Catalog ──
let _cfilter={cat:'all',q:''};
async function viewCatalog(){
  setTop('Zafiyet Kataloğu','');
  if(!S.catalog.length) S.catalog=await get('/api/catalog');
  const cats=['all',...[...new Set(S.catalog.map(e=>e.category))]];
  const render=()=>{
    const list=S.catalog.filter(e=>(_cfilter.cat==='all'||e.category===_cfilter.cat)
      &&(!_cfilter.q||(e.title+(e.summary||'')+(e.tags||[]).join()).toLowerCase().includes(_cfilter.q.toLowerCase())));
    $('#clist').innerHTML=list.map(e=>`<tr class="clk" onclick="location.hash='#/catalog/${e.id}'">
      <td>${sevBadge(e.severity)}</td><td><b>${esc(e.title)}</b><div class="muted" style="font-size:12.5px">${esc(e.summary||'')}</div></td>
      <td>${CAT_TR[e.category]||e.category}</td>
      <td>${(e.cve||[]).slice(0,2).map(c=>`<span class="chip cve">${esc(c)}</span>`).join(' ')}${e.manual_only?' <span class="chip manual">manuel</span>':''}</td></tr>`).join('')
      ||`<tr><td colspan="4" class="empty">Eşleşen kayıt yok.</td></tr>`;
    $('#ccount').textContent=list.length;
  };
  const chips=cats.map(c=>`<span class="fchip ${_cfilter.cat===c?'on':''}" data-cat="${c}">${c==='all'?'Tümü':(CAT_TR[c]||c)}</span>`).join('');
  C().innerHTML=`<div class="filters">${chips}
    <input class="search" id="csearch" type="text" placeholder="Ara: başlık, etiket…" value="${esc(_cfilter.q)}">
    <span class="right muted"><b id="ccount">0</b> kayıt</span></div>
    <div class="card" style="padding:4px 4px 0"><table>
      <thead><tr><th>Önem</th><th>Başlık</th><th>Kategori</th><th>CVE</th></tr></thead>
      <tbody id="clist"></tbody></table></div>`;
  document.querySelectorAll('.fchip').forEach(c=>c.onclick=()=>{_cfilter.cat=c.dataset.cat;
    document.querySelectorAll('.fchip').forEach(x=>x.classList.toggle('on',x===c));render();});
  $('#csearch').oninput=e=>{_cfilter.q=e.target.value;render();};
  render();
}

function kbCard(e){
  const cve=(e.cve||[]).map(c=>`<span class="chip cve">${esc(c)}</span>`).join(' ');
  const mitre=(e.mitre||[]).map(c=>`<span class="chip mitre">${esc(c)}</span>`).join(' ');
  const tags=(e.tags||[]).map(t=>`<span class="chip">${esc(t)}</span>`).join(' ');
  const refs=(e.references||[]).map(r=>`<li><a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a></li>`).join('');
  const sec=(t,v,cls)=>v?`<div class="kb-sec"><h4>${t}</h4>${cls?`<div class="callout ${cls}"><p>${esc(v)}</p></div>`:`<p>${esc(v)}</p>`}</div>`:'';
  return `<div class="card">
    <div class="kb-head">${sevBadge(e.severity)}<h2 style="text-transform:none;letter-spacing:0;color:var(--fg);font-size:17px;margin:0">${esc(e.title)}</h2>
      ${e.manual_only?'<span class="chip manual">sömürü manuel</span>':''}</div>
    <div style="margin:6px 0 16px">${cve} ${mitre} ${tags}</div>
    ${sec('Özet',e.summary)}
    ${sec('Açıklama',e.description)}
    ${sec('Sömürü yolu',e.exploitation,e.manual_only?'crit':'')}
    ${sec('Çözüm önerisi',e.remediation)}
    ${refs?`<div class="kb-sec"><h4>Referanslar</h4><ul style="margin:0;padding-left:18px">${refs}</ul></div>`:''}
  </div>`;
}

async function viewCatalogDetail(id){
  setTop('Katalog kaydı',`<a href="#/catalog">Zafiyet Kataloğu</a>`);
  let e; try{ e=await get('/api/catalog/'+id);}catch(err){ C().innerHTML='<div class="card"><div class="empty">Kayıt bulunamadı.</div></div>'; return; }
  C().innerHTML=`<div class="backlink" onclick="location.hash='#/catalog'">← Zafiyet Kataloğu</div>${kbCard(e)}`;
}

// ── New Scan ──
let _newMode='safe';
async function viewNew(){
  setTop('Yeni Tarama','');
  const d=await get('/api/defaults');
  _newMode=d.mode||'safe';
  const credWarn=d.has_credentials?'':`<div class="callout" style="margin-top:12px">⚠ config.yaml'de kimlik bilgisi yok — kimlik gerektiren modüller atlanır.</div>`;
  C().innerHTML=`<div class="grid" style="grid-template-columns:1fr 1fr;align-items:start">
    <div class="card">
      <h2>Kapsam & Politika</h2>
      <label class="fld">Include ağları (her satıra bir CIDR/IP)</label>
      <textarea id="inc" class="mono" rows="3" placeholder="192.168.1.0/24">${esc((d.include||[]).join('\n'))}</textarea>
      <label class="fld">Hariç (exclude — her zaman kazanır)</label>
      <textarea id="exc" class="mono" rows="2" placeholder="192.168.1.1&#10;192.168.1.30">${esc((d.exclude||[]).join('\n'))}</textarea>
      <label class="fld">Tarama adı (opsiyonel)</label>
      <input id="nm" type="text" placeholder="örn. Lab - Haftalık">
      <label class="fld">Mod</label>
      <div class="row" style="gap:8px">
        <span class="fchip ${_newMode==='safe'?'on':''}" data-mode="safe">Safe</span>
        <span class="fchip ${_newMode==='aggressive'?'on':''}" data-mode="aggressive">Aggressive (intrusive)</span>
      </div>
      <label class="fld" style="margin-top:14px"><input type="checkbox" id="dry"> Dry-run (komutları yaz, çalıştırma)</label>
      ${credWarn}
      <div style="margin-top:18px"><button class="primary" id="startBtn" style="width:100%">▶ Taramayı Başlat</button></div>
    </div>
    <div class="card"><h2>Modüller (plugin)</h2><div id="modpick"></div></div>
  </div>`;
  renderModPick();
  document.querySelectorAll('.fchip[data-mode]').forEach(c=>c.onclick=()=>{_newMode=c.dataset.mode;
    document.querySelectorAll('.fchip[data-mode]').forEach(x=>x.classList.toggle('on',x===c));renderModPick();});
  $('#startBtn').onclick=startScan;
}
function renderModPick(){
  const byPhase={};
  S.modules.forEach(m=>{(byPhase[m.phase]=byPhase[m.phase]||[]).push(m);});
  const html=Object.keys(byPhase).sort((a,b)=>a-b).map(ph=>`
    <div class="phase-group"><div class="phase-h">Faz ${ph}</div>
    ${byPhase[ph].map(m=>{const gated=m.intrusive&&_newMode!=='aggressive';
      return `<label class="mod"><input type="checkbox" class="mchk" value="${m.name}" ${m.default_enabled&&!gated?'checked':''} ${gated?'disabled':''}>
      <div class="mm"><div class="mn">${esc(m.label||m.name)}
        ${m.intrusive?'<span class="chip manual" style="margin-left:6px">intrusive</span>':''}</div>
        <div class="md">${esc(m.description||'')}</div></div></label>`;}).join('')}</div>`).join('');
  $('#modpick').innerHTML=html;
}
async function startScan(){
  const include=$('#inc').value.split('\n').map(s=>s.trim()).filter(Boolean);
  const exclude=$('#exc').value.split('\n').map(s=>s.trim()).filter(Boolean);
  if(!include.length){ alert('En az bir include ağı gir.'); return; }
  const modules=[...document.querySelectorAll('.mchk:checked')].map(c=>c.value);
  const body={name:$('#nm').value.trim()||null,include,exclude,mode:_newMode,modules,dry_run:$('#dry').checked};
  try{ await post('/api/scan',body); location.hash='#/scans'; }
  catch(e){ alert('Hata: '+e.message); }
}

// ── WebSocket (canlı) ──
function connectWS(){
  const ws=new WebSocket(`ws://${location.host}/ws`);
  ws.onmessage=ev=>{
    const m=JSON.parse(ev.data);
    if(m.type==='job'){
      const changed=S.status!==m.status; S.status=m.status; S.job=m.job_id;
      updateStatusPill(m.status);
      const h=location.hash||'#/';
      // Canlı görünümdeysek tazele
      if((h==='#/'||h==='#/scans'||h.startsWith('#/scans/')||h==='#/hosts'||h==='#/findings') && (m.status==='running'||changed))
        router();
    }
  };
  ws.onclose=()=>setTimeout(connectWS,1500);
}
function updateStatusPill(s){
  const p=$('#statuspill'); if(!p)return;
  p.className='st st-'+(s||'idle'); p.textContent=s||'idle';
  p.style.display = (s&&s!=='idle')?'inline-block':'none';
}

// ── boot ──
async function boot(){
  S.modules=await get('/api/modules');
  $('#navcnt-catalog').textContent=(await get('/api/catalog')).length;
  window.addEventListener('hashchange',router);
  connectWS();
  router();
  // aktif durum
  try{ const j=await get('/api/job'); if(j.status) updateStatusPill(j.status);}catch(e){}
}
boot();
