// İç Ağ Recon Paneli — Nessus tarzı SPA (bağımlılıksız)
const SEV = ['critical','high','medium','low','info'];
const SEV_TR = {critical:'Kritik',high:'Yüksek',medium:'Orta',low:'Düşük',info:'Bilgi'};
const SEV_COLOR = {critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22d3ee',info:'#8fa0b3'};
const CAT_TR = {vuln:'Zafiyet',config:'Yapılandırma',cred:'Kimlik Bilgisi',service:'Servis',info:'Bilgi'};
const FAM = {discovery:'Keşif',portscan:'Port & Servis',quickcve:'Hızlı CVE',
  smb:'SMB / NetBIOS',ad:'Active Directory',kerberos:'Kerberos',
  poison:'Ağ Zehirleme / Relay',postcred:'Kimlikli Post-Enum'};
const FAM_ORDER = ['discovery','portscan','quickcve','smb','ad','kerberos','postcred','poison'];
const BASE_MODULES = ['discovery','portscan']; // her zaman çalışan temel keşif

const S = { modules:[], builtNames:new Set(), catalog:[], status:'idle', activeJob:null };

const $ = s => document.querySelector(s);
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function get(u){ const r=await fetch(u); if(!r.ok) throw new Error((await r.json().catch(()=>({}))).detail||r.status); return r.json(); }
async function post(u,b){ const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});
  if(!r.ok) throw new Error((await r.json().catch(()=>({}))).detail||r.status); return r.json(); }
const fmtTime = ts => ts? new Date(ts*1000).toLocaleString('tr-TR',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}) : '—';
const ST_TR = {saved:'hazır',pending:'bekliyor',running:'çalışıyor',done:'bitti',failed:'hata',stopped:'durduruldu'};
const sevBadge = s => `<span class="sev sev-${s}">${SEV_TR[s]||s}</span>`;
const stBadge = s => `<span class="st st-${s}">${ST_TR[s]||s}</span>`;
function miniBars(counts){ return `<span class="minibars">`+SEV.map(s=>{const n=counts[s]||0; if(!n)return '';
  const h=Math.min(18,6+n*2); return `<i class="bg-${s}" style="height:${h}px" title="${SEV_TR[s]}: ${n}"></i>`;}).join('')+`</span>`; }

// ── router ──
const routes = [
  [/^#\/?$/, ()=>location.hash='#/scans'],
  [/^#\/scans$/, viewScans],
  [/^#\/scans\/([^/]+)\/f\/(.+)$/, viewFinding],
  [/^#\/scans\/([^/]+)$/, viewScanDetail],
  [/^#\/new$/, viewNew],
];
function router(){
  const h=location.hash||'#/';
  for(const [re,fn] of routes){ const m=h.match(re); if(m){ setActiveNav(h); fn(...m.slice(1)); return; } }
  location.hash='#/scans';
}
function setActiveNav(h){ document.querySelectorAll('.nav a').forEach(a=>a.classList.toggle('active',h.startsWith('#/scans'))); }
function setTop(title,crumb){ $('#ttl').textContent=title; $('#crumb').innerHTML=crumb?`<span class="crumb">${crumb}</span>`:''; }
const C = () => $('#content');

// ── Taramalar listesi ──
async function viewScans(){
  setTop('Taramalar','');
  const scans=await get('/api/scans');
  $('#navcnt-scans').textContent=scans.length;
  if(!scans.length){ C().innerHTML=`<div class="card"><div class="empty">Henüz tarama yok.<br><br>
    <button class="primary" onclick="location.hash='#/new'">+ Yeni tarama oluştur</button></div></div>`; return; }
  const actBtn=s=>{
    if(s.status==='running') return `<button class="ibtn danger" onclick="event.stopPropagation();stopScan()" title="Durdur">■</button>`;
    const label = s.status==='saved' ? '▶' : '⟳';
    const tip = s.status==='saved' ? 'Başlat' : 'Yeniden çalıştır';
    return `<button class="ibtn go" onclick="event.stopPropagation();launchScan('${s.id}')" title="${tip}">${label}</button>`;
  };
  const rows=scans.map(s=>`<tr class="clk" onclick="location.hash='#/scans/${s.id}'">
    <td><b>${esc(s.name)}</b><div class="muted mono" style="font-size:12px">${esc((s.include||[]).join(', '))}</div></td>
    <td>${stBadge(s.status)}</td>
    <td>${s.credentialed?`<span class="chip">👤 ${esc(s.credential_principal||'kimlikli')}</span>`:'<span class="muted">anonim</span>'}</td>
    <td class="num">${s.hosts}</td><td class="num">${s.total}</td><td>${miniBars(s.severity_counts)}</td>
    <td class="muted">${s.started_at?fmtTime(s.started_at):'—'}</td>
    <td style="text-align:right">${actBtn(s)}</td></tr>`).join('');
  C().innerHTML=`<div class="row" style="justify-content:flex-end;margin-bottom:14px">
      <button class="primary" onclick="location.hash='#/new'">+ Yeni Tarama</button></div>
    <div class="card tablecard"><table>
    <thead><tr><th>Tarama</th><th>Durum</th><th>Kimlik</th><th>Host</th><th>Bulgu</th><th>Önem</th><th>Başlangıç</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

// ── Tarama detayı (Nessus sekmeleri) ──
let _sdTab='findings';
async function viewScanDetail(id){
  setTop('Tarama','<a href="#/scans">Taramalar</a>');
  const d=await get('/api/scans/'+id);
  const credLine = d.credentialed?`<span class="chip">👤 ${esc(d.credential_principal)}</span>`:'<span class="muted">anonim tarama</span>';
  const head=`
    <div class="detail-head">
      <div>
        <div class="dh-title">${esc(d.name)} ${stBadge(d.status)}</div>
        <div class="dh-sub">${credLine} · <span class="mono">${esc((d.include||[]).join(', '))}</span> · ${fmtTime(d.started_at)}${d.dry_run?' · <span class="chip">dry-run</span>':''}</div>
        ${d.description?`<div class="muted" style="margin-top:4px">${esc(d.description)}</div>`:''}
      </div>
      <div>${
        d.status==='running' ? `<button class="danger" onclick="stopScan()">■ Durdur</button>`
        : d.status==='saved' ? `<button class="primary" onclick="launchScan('${id}')">▶ Taramayı Başlat</button>`
        : `<button onclick="launchScan('${id}')">⟳ Yeniden Çalıştır</button>`
      }</div>
    </div>
    <div class="tabs">
      <span class="tab ${_sdTab==='findings'?'on':''}" onclick="sdTab('findings','${id}')">Bulgular <span class="tcount">${d.total}</span></span>
      <span class="tab ${_sdTab==='hosts'?'on':''}" onclick="sdTab('hosts','${id}')">Hostlar <span class="tcount">${d.hosts}</span></span>
      <span class="tab ${_sdTab==='progress'?'on':''}" onclick="sdTab('progress','${id}')">İlerleme</span>
    </div>`;
  C().innerHTML=head+`<div id="sdbody"></div>`;
  renderSdBody(id,d);
}
window.sdTab=(t,id)=>{ _sdTab=t; viewScanDetail(id); };
window.stopScan=async()=>{ await post('/api/stop'); };
window.launchScan=async(id)=>{
  try{ await post('/api/scans/'+id+'/launch'); _sdTab='progress'; location.hash='#/scans/'+id; router(); }
  catch(e){ alert('Başlatılamadı: '+e.message); }
};

async function renderSdBody(id,d){
  const body=$('#sdbody'); if(!body)return;
  if(_sdTab==='findings'){
    if(d.status==='saved'){ body.innerHTML=`<div class="card"><div class="empty">
      Tarama henüz çalıştırılmadı.<br><br>
      <button class="primary" onclick="launchScan('${id}')">▶ Taramayı Başlat</button></div></div>`; return; }
    const f=await get('/api/findings?job_id='+id);
    if(!f.length){ body.innerHTML=`<div class="card"><div class="empty">${d.status==='running'?'Taranıyor… bulgu bekleniyor.':'Bu taramada bulgu yok.'}</div></div>`; return; }
    const rows=f.map(x=>`<tr class="clk" onclick="location.hash='#/scans/${id}/f/${encodeURIComponent(x.id)}'">
      <td>${sevBadge(x.severity)}</td><td>${esc(x.title)}${x.manual_followup?' <span class="chip manual">MANUEL</span>':''}</td>
      <td class="mono">${esc(x.host)}</td><td class="mono">${x.port||''}</td>
      <td><span class="chip">${x.confidence}</span></td><td class="muted">${esc(x.source_tool||'')}</td></tr>`).join('');
    body.innerHTML=`<div class="card tablecard"><table>
      <thead><tr><th>Önem</th><th>Başlık</th><th>Host</th><th>Port</th><th>Güven</th><th>Araç</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  } else if(_sdTab==='hosts'){
    const inv=await get('/api/hosts?job_id='+id); const hosts=inv.hosts||{};
    const keys=Object.keys(hosts);
    if(!keys.length){ body.innerHTML=`<div class="card"><div class="empty">Host envanteri boş.</div></div>`; return; }
    const rows=keys.map(ip=>{const h=hosts[ip];
      const roles=(h.roles||[]).map(r=>`<span class="chip role">${r}</span>`).join(' ');
      return `<tr><td class="mono"><b>${esc(ip)}</b></td><td>${esc(h.hostname||'')}</td>
        <td class="muted">${esc(h.os||'—')}</td><td>${roles||'<span class="muted">—</span>'}</td>
        <td class="num">${(h.ports||[]).length}</td>
        <td>${h.smb_signing===false?'<span class="chip manual">signing yok</span>':'<span class="muted">—</span>'}</td>
        <td class="num">${h.finding_count||0}</td></tr>`;}).join('');
    body.innerHTML=`<div class="card tablecard"><table>
      <thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Roller</th><th>Port</th><th>SMB</th><th>Bulgu</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  } else {
    const prog=S.modules.map(m=>{const st=d.module_status[m.name]||{}; const s=st.status||'pending';
      return `<div class="prow"><span class="pdot ${s}"></span><span class="pn">${m.label||m.name}</span>
        <span class="pm">${s}${st.message?' · '+esc(st.message):''}</span></div>`;}).join('');
    const ev=(d.events||[]).map(e=>`<div class="e-${e.status}">${fmtTime(e.ts).split(' ').pop()}  ${e.module}  [${e.status}]  ${esc(e.message||'')}</div>`).join('');
    body.innerHTML=`<div class="grid" style="grid-template-columns:1fr 1fr">
      <div class="card"><h2>Faz ilerlemesi</h2><div class="plist">${prog}</div></div>
      <div class="card"><h2>Olay akışı</h2><div class="log">${ev||'<span class="muted">—</span>'}</div></div></div>`;
  }
}

// ── Bulgu detayı (katalog kartı gömülü) ──
async function viewFinding(id,fid){
  fid=decodeURIComponent(fid);
  setTop('Bulgu',`<a href="#/scans">Taramalar</a> / <a href="#/scans/${id}">tarama</a>`);
  const finds=await get('/api/findings?job_id='+id);
  const f=finds.find(x=>x.id===fid);
  if(!f){ C().innerHTML='<div class="card"><div class="empty">Bulgu bulunamadı.</div></div>'; return; }
  let kb=null; if(f.kb_id){ try{ kb=await get('/api/catalog/'+f.kb_id);}catch(e){} }
  C().innerHTML=`<div class="backlink" onclick="history.back()">← Geri</div>
    <div class="card" style="margin-bottom:16px">
      <div class="kb-head">${sevBadge(f.severity)}<h1 style="margin:0;font-size:20px">${esc(f.title)}</h1></div>
      <div class="kv" style="margin-top:12px">
        <span class="k">Host</span><span class="mono">${esc(f.host)}${f.port?':'+f.port:''}</span>
        <span class="k">Faz</span><span>${esc(f.phase)}</span>
        <span class="k">Güven</span><span>${f.confidence}</span>
        <span class="k">Sömürülebilir</span><span>${f.exploitable}${f.manual_followup?' <span class="chip manual">MANUEL DOĞRULA</span>':''}</span>
        <span class="k">Kaynak araç</span><span>${esc(f.source_tool||'—')}</span>
        <span class="k">Kanıt</span><span class="mono" style="font-size:12px">${esc(f.evidence_path||'—')}</span>
        ${f.notes?`<span class="k">Not</span><span>${esc(f.notes)}</span>`:''}
      </div></div>
    ${kb?kbCard(kb):'<div class="card muted">Bu bulgu için katalog kaydı yok.</div>'}`;
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
    ${sec('Özet',e.summary)}${sec('Açıklama',e.description)}
    ${sec('Sömürü yolu',e.exploitation,e.manual_only?'crit':'')}
    ${sec('Çözüm önerisi',e.remediation)}
    ${refs?`<div class="kb-sec"><h4>Referanslar</h4><ul style="margin:0;padding-left:18px">${refs}</ul></div>`:''}</div>`;
}

// ── Yeni Tarama (sekmeli) ──
let _newTab='settings';
let _cred=false;             // kimlikli mi
let _pluginSel=null;         // Set<kb_id> | null(hepsi)
async function viewNew(){
  setTop('Yeni Tarama','<a href="#/scans">Taramalar</a>');
  if(!S.catalog.length) S.catalog=await get('/api/catalog');
  const d=await get('/api/defaults');
  if(_pluginSel===null){ _pluginSel=new Set(S.catalog.map(e=>e.id)); } // varsayılan: hepsi
  window._defaults=d;
  C().innerHTML=`
    <div class="card" style="padding:0;overflow:hidden">
      <div class="tabs tabs-pad">
        <span class="tab ${_newTab==='settings'?'on':''}" onclick="newTab('settings')">Ayarlar</span>
        <span class="tab ${_newTab==='creds'?'on':''}" onclick="newTab('creds')">Kimlik Bilgileri</span>
        <span class="tab ${_newTab==='plugins'?'on':''}" onclick="newTab('plugins')">Pluginler <span class="tcount" id="pcount"></span></span>
      </div>
      <div id="newbody" style="padding:20px"></div>
      <div class="form-foot">
        <button onclick="location.hash='#/scans'">İptal</button>
        <button class="primary" id="saveBtn">💾 Tarama Kaydet</button>
      </div>
    </div>`;
  renderNewBody();
  $('#saveBtn').onclick=saveScan;
  updatePCount();
}
window.newTab=(t)=>{ saveSettings(); _newTab=t; renderNewBody(); };
function saveSettings(){ // sekme değişince form değerlerini sakla
  const g=id=>{const e=$('#'+id);return e?e.value:undefined;};
  const chk=id=>{const e=$('#'+id);return e?e.checked:undefined;};
  if($('#inc')!==null){ window._f={inc:g('inc'),exc:g('exc'),nm:g('nm'),desc:g('desc'),dry:chk('dry')}; }
  if($('#cu')!==null){ window._c={dom:g('cdom'),user:g('cu'),pw:g('cpw'),hash:g('chash')}; _cred=chk('credon'); }
}
function renderNewBody(){
  const f=window._f||{}, d=window._defaults||{}, c=window._c||{};
  const body=$('#newbody');
  if(_newTab==='settings'){
    body.innerHTML=`
      <label class="fld">Tarama adı</label>
      <input id="nm" type="text" placeholder="örn. Lab - İç Ağ" value="${esc(f.nm||'')}">
      <label class="fld">Açıklama (opsiyonel)</label>
      <input id="desc" type="text" placeholder="kısa not" value="${esc(f.desc||'')}">
      <label class="fld">Hedefler — include (her satıra bir CIDR/IP)</label>
      <textarea id="inc" class="mono" rows="3" placeholder="192.168.1.0/24">${esc(f.inc!==undefined?f.inc:(d.include||[]).join('\n'))}</textarea>
      <label class="fld">Hariç — exclude (her zaman kazanır)</label>
      <textarea id="exc" class="mono" rows="2" placeholder="192.168.1.1&#10;192.168.1.30">${esc(f.exc!==undefined?f.exc:(d.exclude||[]).join('\n'))}</textarea>
      <label class="fld" style="margin-top:14px"><input type="checkbox" id="dry" ${f.dry?'checked':''}> Dry-run (komutları yaz, çalıştırma)</label>`;
  } else if(_newTab==='creds'){
    body.innerHTML=`
      <div class="seg">
        <span class="segbtn ${!_cred?'on':''}" onclick="setCred(false)">Anonim tarama</span>
        <span class="segbtn ${_cred?'on':''}" onclick="setCred(true)">Kimlikli (Windows / AD)</span>
      </div>
      <input type="checkbox" id="credon" ${_cred?'checked':''} style="display:none">
      <div class="muted" style="margin:12px 0">${_cred
        ? 'Domain kullanıcısıyla AD/SMB numaralandırma (Kerberoast, share, LDAP) yapılır. Parola yalnızca bellekte tutulur, loga/diske yazılmaz.'
        : 'Kimlik bilgisi olmadan — yalnız anonim/null erişim ve ağ seviyesi tespit.'}</div>
      <div class="${_cred?'':'disabled-block'}">
        <div class="row">
          <div style="flex:1;min-width:160px"><label class="fld">Domain</label>
            <input id="cdom" type="text" autocomplete="off" placeholder="lab.local" value="${esc(c.dom||'')}" ${_cred?'':'disabled'}></div>
          <div style="flex:1;min-width:160px"><label class="fld">Kullanıcı adı</label>
            <input id="cu" type="text" autocomplete="off" placeholder="lowpriv" value="${esc(c.user||'')}" ${_cred?'':'disabled'}></div>
        </div>
        <label class="fld">Parola</label>
        <div class="pw-wrap">
          <input id="cpw" type="password" autocomplete="new-password" placeholder="parola" value="${esc(c.pw||'')}" ${_cred?'':'disabled'}>
          <span class="pw-toggle" id="pwtgl" onclick="togglePw()">göster</span>
        </div>
        <label class="fld">— veya NTLM hash (pass-the-hash)</label>
        <input id="chash" class="mono" type="text" autocomplete="off" placeholder="aad3b4...:31d6cf..." value="${esc(c.hash||'')}" ${_cred?'':'disabled'}>
      </div>`;
  } else {
    renderPlugins(body);
  }
  updatePCount();
}
window.setCred=(v)=>{ saveSettings(); _cred=v; renderNewBody(); };
window.togglePw=()=>{ const i=$('#cpw'); if(!i)return; i.type=i.type==='password'?'text':'password';
  const t=$('#pwtgl'); if(t)t.textContent=i.type==='password'?'göster':'gizle'; };

function renderPlugins(body){
  const byFam={}; S.catalog.forEach(e=>{(byFam[e.phase]=byFam[e.phase]||[]).push(e);});
  const fams=FAM_ORDER.filter(p=>byFam[p]).concat(Object.keys(byFam).filter(p=>!FAM_ORDER.includes(p)));
  const total=S.catalog.length, sel=_pluginSel.size;
  let html=`<div class="plugbar">
    <label class="selall"><input type="checkbox" id="selall" ${sel===total?'checked':''}> Tümünü seç</label>
    <span class="right muted"><b id="selcount">${sel}</b> / ${total} plugin seçili</span></div>`;
  html+=fams.map(p=>{
    const items=byFam[p]; const ids=items.map(i=>i.id);
    const on=ids.filter(i=>_pluginSel.has(i)).length;
    const built=S.builtNames.has(p);
    return `<div class="fam">
      <div class="fam-h">
        <label><input type="checkbox" class="famchk" data-fam="${p}" ${on===ids.length?'checked':''} ${on>0&&on<ids.length?'indeterminate':''}>
        <b>${FAM[p]||p}</b></label>
        ${built?'':'<span class="chip" style="margin-left:8px">yakında</span>'}
        <span class="right muted">${on}/${ids.length}</span>
      </div>
      <div class="fam-body">${items.map(i=>`<label class="plg">
        <input type="checkbox" class="plgchk" data-id="${i.id}" data-fam="${p}" ${_pluginSel.has(i.id)?'checked':''}>
        ${sevBadge(i.severity)} <span class="pn2">${esc(i.title)}</span>
        <span class="muted pd">${esc(i.summary||'')}</span></label>`).join('')}</div>
    </div>`;}).join('');
  body.innerHTML=html;
  // indeterminate state
  document.querySelectorAll('.famchk').forEach(ch=>{const fam=ch.dataset.fam;
    const ids=byFam[fam].map(i=>i.id); const on=ids.filter(i=>_pluginSel.has(i)).length;
    ch.indeterminate = on>0 && on<ids.length;});
  // handlers
  $('#selall').onchange=e=>{ if(e.target.checked)_pluginSel=new Set(S.catalog.map(x=>x.id)); else _pluginSel=new Set(); renderPlugins(body); };
  document.querySelectorAll('.famchk').forEach(ch=>ch.onchange=()=>{const fam=ch.dataset.fam;
    byFam[fam].forEach(i=>{ if(ch.checked)_pluginSel.add(i.id); else _pluginSel.delete(i.id);}); renderPlugins(body);});
  document.querySelectorAll('.plgchk').forEach(ch=>ch.onchange=()=>{ if(ch.checked)_pluginSel.add(ch.dataset.id); else _pluginSel.delete(ch.dataset.id); renderPlugins(body);});
  updatePCount();
}
function updatePCount(){ const el=$('#pcount'); if(el&&_pluginSel) el.textContent=_pluginSel.size; }

async function saveScan(){
  saveSettings();
  const f=window._f||{}, c=window._c||{};
  const include=(f.inc||'').split('\n').map(s=>s.trim()).filter(Boolean);
  const exclude=(f.exc||'').split('\n').map(s=>s.trim()).filter(Boolean);
  if(!include.length){ alert('Ayarlar sekmesinde en az bir hedef (include) gir.'); _newTab='settings'; renderNewBody(); return; }
  // seçili pluginlerden modülleri türet (temel keşif her zaman)
  const selPhases=new Set(S.catalog.filter(e=>_pluginSel.has(e.id)).map(e=>e.phase));
  const modules=[...new Set([...BASE_MODULES, ...[...selPhases].filter(p=>S.builtNames.has(p))])];
  const body={name:f.nm||null, description:f.desc||null, include, exclude,
    modules, plugins:[..._pluginSel], dry_run:!!f.dry};
  if(_cred && c.user){ body.credential={domain:c.dom||null, username:c.user, password:c.pw||null, ntlm_hash:c.hash||null}; }
  try{ await post('/api/scans',body); resetNew(); location.hash='#/scans'; }
  catch(e){ alert('Kaydedilemedi: '+e.message); }
}
function resetNew(){ _newTab='settings'; _cred=false; _pluginSel=null; window._f=null; window._c=null; }

// ── WebSocket (canlı) ──
function connectWS(){
  const ws=new WebSocket(`ws://${location.host}/ws`);
  ws.onmessage=ev=>{ const m=JSON.parse(ev.data);
    if(m.type==='job'){ const changed=S.status!==m.status; S.status=m.status; S.activeJob=m.job_id;
      updateStatusPill(m.status);
      const h=location.hash||'#/';
      if((h==='#/scans'||h===('#/scans/'+m.job_id)) && (m.status==='running'||changed)) router();
    }};
  ws.onclose=()=>setTimeout(connectWS,1500);
}
function updateStatusPill(s){ const p=$('#statuspill'); if(!p)return;
  p.className='st st-running'; p.textContent='● tarama çalışıyor';
  p.style.display=(s==='running')?'inline-block':'none'; }

// ── boot ──
async function boot(){
  S.modules=await get('/api/modules');
  S.builtNames=new Set(S.modules.map(m=>m.name));
  window.addEventListener('hashchange',router);
  connectWS();
  router();
  try{ const j=await get('/api/job'); if(j.status) updateStatusPill(j.status);}catch(e){}
}
boot();
