/**
 * graphs.js v3.0
 * ─────────────────────────────────────────────────────────────────
 * TWO COMPLETELY SEPARATE GRAPH SYSTEMS — NO SHARED STATE:
 *
 * 1. Radial Dashboard (renderDashboardCharts)
 *    SOC intelligence dashboard: severity cards, donut, gauge, radar,
 *    services, CVE table, bar chart, activity feed.
 *    Chart.js only. No D3. No expansion logic.
 *
 * 2. OSINT Framework Graph (buildOsintTree)
 *    Progressive click-to-expand intelligence tree.
 *    STARTS FULLY COLLAPSED — only host node visible.
 *    D3 horizontal tree. No Chart.js. No SOC widgets.
 *    Behaves like osintframework.com: reveal info progressively.
 *
 * Isolation guarantees:
 *   - Separate state objects: _charts vs _osint.*
 *   - destroyAll() only destroys Chart.js instances
 *   - clearOsint() only clears D3 SVG
 *   - No shared IDs, no shared render functions
 *   - switchDashTab ensures only one system is visible
 * ─────────────────────────────────────────────────────────────────
 */

const Graphs = (() => {

  /* ══════════════════════════════════════════════════════════════
     SECTION A — CHART.JS REGISTRY  (Radial dashboard only)
  ══════════════════════════════════════════════════════════════ */

  const _charts = {};   // isolated Chart.js registry — never touched by OSINT code

  function _dc(id) {
    if (_charts[id]) { try { _charts[id].destroy(); } catch(_) {} delete _charts[id]; }
  }

  function destroyAll() {
    Object.keys(_charts).forEach(k => _dc(k));
    // NOTE: intentionally does NOT touch _osint.* state
  }

  const C = {
    critical : '#e24b4a',
    high     : '#ef9f27',
    medium   : '#378add',
    low      : '#1d9e75',
    text     : '#8b949e',
    text1    : '#e6edf3',
    bg       : '#0f1623',
    border   : '#1e2a3a',
  };

  /* ══════════════════════════════════════════════════════════════
     SECTION B — SOC INTELLIGENCE DASHBOARD (Radial)
     All renderDashboard* functions isolated here.
     They touch only Canvas elements and #soc-* DOM ids.
  ══════════════════════════════════════════════════════════════ */

  function renderDashboardCharts(ch, risk) {
    const emptyEl = document.getElementById('dash-empty');
    if (emptyEl) emptyEl.style.display = 'none';
    ['soc-row1','soc-row2','soc-row3'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'grid';
    });

    const rs    = risk?.hosts?.[0]?.risk_summary || {};
    const cnt   = rs.counts  || {};
    const crit  = cnt.critical || 0;
    const high  = cnt.high     || 0;
    const med   = cnt.medium   || 0;
    const low   = cnt.low      || 0;
    const total = Math.max(1, crit + high + med + low);
    const pct   = n => Math.round(n / total * 1000) / 10;

    _renderSeverityCard('critical', crit, pct(crit), C.critical);
    _renderSeverityCard('high',     high, pct(high), C.high);
    _renderSeverityCard('medium',   med,  pct(med),  C.medium);
    _renderSeverityCard('low',      low,  pct(low),  C.low);
    _renderDonut(crit, high, med, low, total);

    const gd       = ch?.risk_gauge || {};
    const scoreVal = typeof gd.value === 'number' ? gd.value : parseInt(gd.value) || 0;
    _renderGauge(scoreVal, gd.label || 'MEDIUM RISK', risk);
    _renderRadar(ch, risk, scoreVal);
    _renderServices(risk);
    _renderCVETable(risk);
    _renderCVEBar(ch, risk);
    _renderActivityFeed(risk);
  }

  function _renderSeverityCard(sev, count, pctVal, color) {
    const nEl = document.getElementById(`scard-n-${sev}`);
    const pEl = document.getElementById(`scard-p-${sev}`);
    if (nEl) nEl.textContent = count;
    if (pEl) pEl.textContent = `${pctVal}% of findings`;

    const canvasId = `spark-${sev}`;
    _dc(canvasId);
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const base = Math.max(1, count);
    const data = Array.from({length: 12}, (_, i) =>
      Math.max(0, Math.round(base * (0.5 + (i / 11) * 0.5 + (Math.random() * 0.4 - 0.2))))
    );
    _charts[canvasId] = new Chart(canvas, {
      type: 'line',
      data: {
        labels: data.map((_, i) => i),
        datasets: [{ data, borderColor: color, backgroundColor: color + '22', borderWidth: 1.5, pointRadius: 0, tension: 0.4, fill: true }],
      },
      options: {
        responsive: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: { x: { display: false }, y: { display: false, beginAtZero: true } },
        animation: { duration: 1200, easing: 'easeInOutQuart' },
      },
    });
  }

  function _renderDonut(crit, high, med, low, total) {
    const totalEl = document.getElementById('donut-total');
    if (totalEl) totalEl.textContent = crit + high + med + low;
    const pct = n => `${n} (${Math.round(n / total * 1000) / 10}%)`;
    [['critical',crit],['high',high],['medium',med],['low',low]].forEach(([k,v]) => {
      const el = document.getElementById(`sdl-${k}`);
      if (el) el.textContent = pct(v);
    });
    _dc('soc-donut');
    const canvas = document.getElementById('ch-risk-donut');
    if (!canvas) return;
    _charts['soc-donut'] = new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: ['Critical','High','Medium','Low'],
        datasets: [{
          data: [crit, high, med, low],
          backgroundColor: [C.critical+'cc', C.high+'cc', C.medium+'cc', C.low+'cc'],
          borderColor:     [C.critical,      C.high,      C.medium,      C.low],
          borderWidth: 1.5, hoverBorderWidth: 2.5, hoverOffset: 4,
        }],
      },
      options: {
        cutout: '70%', responsive: true, maintainAspectRatio: true,
        plugins: { legend: { display: false }, tooltip: {
          callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed} (${Math.round(ctx.parsed/total*1000)/10}%)` },
          backgroundColor: '#0f1623', borderColor: '#1e2a3a', borderWidth: 1,
          titleColor: '#e6edf3', bodyColor: '#8b949e', padding: 10,
        }},
        animation: { animateRotate: true, duration: 1200 },
      },
    });
  }

  function _renderGauge(score, riskLabel, risk) {
    const scoreEl  = document.getElementById('gauge-score');
    const riskEl   = document.getElementById('gauge-risk-label');
    const targetEl = document.getElementById('gauge-target-meta');
    const durEl    = document.getElementById('gauge-duration-meta');
    const host     = risk?.hosts?.[0] || {};
    const target   = risk?.target || host.ip || '—';
    const duration = risk?.duration ? _fmtDuration(risk.duration) : '—';
    const svcCount = (host.ports || []).length;
    const leaks    = (host.ports || []).filter(p => (p.cves || []).some(c => c.severity === 'critical')).length;
    const vulnDens = score > 70 ? 'High' : score > 40 ? 'Medium' : 'Low';
    const gaugeColor = score >= 70 ? C.critical : score >= 40 ? C.high : score >= 20 ? C.medium : C.low;
    if (scoreEl)  scoreEl.textContent  = score;
    if (targetEl) targetEl.textContent = `Scan Target: ${target}`;
    if (durEl)    durEl.textContent    = `Scan Duration: ${duration}`;
    if (riskEl)   { riskEl.textContent = riskLabel.toUpperCase(); riskEl.style.color = gaugeColor; }
    const atkEl = document.getElementById('gg-attack');
    const vdEl  = document.getElementById('gg-vulndens');
    const expEl = document.getElementById('gg-exposed');
    const lkEl  = document.getElementById('gg-leaks');
    if (atkEl) { atkEl.textContent = score >= 70 ? 'High' : score >= 40 ? 'Medium' : 'Low'; atkEl.className = `sgr-val sgr-val--${score >= 70 ? 'high' : 'medium'}`; }
    if (vdEl)  { vdEl.textContent  = vulnDens; vdEl.className = `sgr-val sgr-val--${score >= 70 ? 'high' : 'medium'}`; }
    if (expEl)  expEl.textContent  = svcCount;
    if (lkEl)   lkEl.textContent   = leaks;
    const canvas = document.getElementById('ch-gauge-arc');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = 200, H = 120;
    canvas.width = W; canvas.height = H;
    const cx = W / 2, cy = H - 14, r = 82;
    const startAngle = Math.PI, targetAngle = startAngle + (score / 100) * Math.PI;
    let currentAngle = startAngle;
    const dur = 1400, t0 = performance.now();
    const easeOut = t => 1 - Math.pow(1 - t, 3);
    function animate(now) {
      const progress = Math.min(1, (now - t0) / dur);
      currentAngle   = startAngle + easeOut(progress) * (targetAngle - startAngle);
      ctx.clearRect(0, 0, W, H);
      ctx.beginPath(); ctx.arc(cx, cy, r, Math.PI, 2*Math.PI);
      ctx.strokeStyle = '#1a2030'; ctx.lineWidth = 14; ctx.lineCap = 'round'; ctx.stroke();
      ctx.save();
      ctx.shadowColor = gaugeColor; ctx.shadowBlur = 12;
      ctx.beginPath(); ctx.arc(cx, cy, r, startAngle, currentAngle);
      ctx.strokeStyle = gaugeColor; ctx.lineWidth = 14; ctx.lineCap = 'round'; ctx.stroke();
      ctx.restore();
      const nx = cx + r * Math.cos(currentAngle), ny = cy + r * Math.sin(currentAngle);
      ctx.beginPath(); ctx.arc(nx, ny, 6, 0, Math.PI*2);
      ctx.fillStyle = '#fff'; ctx.shadowColor = gaugeColor; ctx.shadowBlur = 10; ctx.fill();
      if (progress < 1) requestAnimationFrame(animate);
    }
    requestAnimationFrame(animate);
  }

  function _renderRadar(ch, risk, score) {
    _dc('soc-radar');
    const canvas = document.getElementById('ch-radar');
    if (!canvas) return;
    const host  = risk?.hosts?.[0] || {};
    const cnt   = host.risk_summary?.counts || {};
    const ports = host.ports || [];
    const expl  = Math.min(100, (cnt.critical || 0)*15 + (cnt.high || 0)*8);
    const impact = Math.min(100, score + Math.random()*5);
    const prev  = Math.min(100, (cnt.medium || 0)*4 + (cnt.high || 0)*6);
    const detect = Math.min(100, 40 + ports.length*3);
    const atk   = Math.min(100, ports.length*8);
    _charts['soc-radar'] = new Chart(canvas, {
      type: 'radar',
      data: {
        labels: ['Exploitability','Impact','Prevalence','Detectability','Attack Surface'],
        datasets: [{ data: [expl,impact,prev,detect,atk], backgroundColor: 'rgba(55,138,221,0.15)', borderColor: '#378add', borderWidth: 2, pointBackgroundColor: '#378add', pointBorderColor: '#fff', pointRadius: 4, pointHoverRadius: 6 }],
      },
      options: {
        responsive: true, maintainAspectRatio: true,
        scales: { r: { min: 0, max: 100, ticks: { display: false, stepSize: 25 }, grid: { color: '#1e2a3a', lineWidth: 1 }, angleLines: { color: '#1e2a3a' }, pointLabels: { color: '#8b949e', font: { size: 10 } } } },
        plugins: { legend: { display: false }, tooltip: { backgroundColor: '#0f1623', borderColor: '#1e2a3a', borderWidth: 1, titleColor: '#e6edf3', bodyColor: '#8b949e', padding: 10 } },
        animation: { duration: 1400, easing: 'easeInOutQuart' },
      },
    });
    const riskLabel = score >= 70 ? 'HIGH RISK' : score >= 40 ? 'MEDIUM RISK' : 'LOW RISK';
    const riskColor = score >= 70 ? C.critical : score >= 40 ? C.high : C.low;
    const riskDesc  = score >= 70 ? 'High risk level with critical vulnerabilities requiring immediate attention.' : score >= 40 ? 'Moderate risk level with several vulnerabilities that should be addressed.' : 'Low risk level. Continue monitoring and applying best practices.';
    const rlEl = document.getElementById('radar-risk-label');
    const rdEl = document.getElementById('radar-risk-desc');
    if (rlEl) { rlEl.textContent = riskLabel; rlEl.style.color = riskColor; }
    if (rdEl) rdEl.textContent = riskDesc;
  }

  function _renderServices(risk) {
    const el = document.getElementById('soc-services-list');
    if (!el) return;
    const ports  = risk?.hosts?.[0]?.ports || [];
    const svcMap = {};
    ports.forEach(p => {
      const svc = (p.service || 'unknown').toUpperCase();
      if (!svcMap[svc]) svcMap[svc] = { count: 0, worstSev: 'low' };
      svcMap[svc].count++;
      const sev = p.risk?.level || 'low';
      const SEV = { critical:3, high:2, medium:1, low:0 };
      if ((SEV[sev]||0) > (SEV[svcMap[svc].worstSev]||0)) svcMap[svc].worstSev = sev;
    });
    const sorted  = Object.entries(svcMap).sort((a,b)=>b[1].count-a[1].count).slice(0,5);
    if (!sorted.length) { el.innerHTML = '<div style="color:#4a5568;font-size:12px;padding:8px 0">No services detected</div>'; return; }
    const maxCount = sorted[0][1].count || 1;
    const ICON = { HTTP:'🌐',HTTPS:'🔒',SMTP:'✉',FTP:'📁',SSH:'💻',SMB:'🗂',MYSQL:'🗄',DNS:'📡',RDP:'🖥',REDIS:'🔴',DEFAULT:'🔌' };
    el.innerHTML = sorted.map(([name,info],i) => {
      const barWidth = Math.round((info.count/maxCount)*100);
      return `<div class="svc-row" style="animation-delay:${i*.06}s">
        <span class="svc-icon">${ICON[name]||ICON.DEFAULT}</span>
        <span class="svc-name">${name}</span>
        <div class="svc-bar-wrap"><div class="svc-bar" data-width="${barWidth}" style="width:0"></div></div>
        <span class="svc-count">${info.count}</span>
        <span class="svc-badge svc-badge--${info.worstSev}">${info.count} ${info.worstSev.charAt(0).toUpperCase()+info.worstSev.slice(1)}</span>
      </div>`;
    }).join('');
    requestAnimationFrame(() => {
      el.querySelectorAll('.svc-bar').forEach(bar => { setTimeout(() => { bar.style.width = `${bar.dataset.width}%`; }, 80); });
    });
  }

  function _renderCVETable(risk) {
    const body  = document.getElementById('sct-body');
    if (!body) return;
    const ports = risk?.hosts?.[0]?.ports || [];
    const allCVEs = [];
    ports.forEach(p => {
      (p.cves || []).forEach(cve => allCVEs.push({ id: cve.cve_id||'?', sev: cve.severity||'unknown', service: (p.service||'unknown').toUpperCase(), cvss: parseFloat(cve.cvss_score||0).toFixed(1) }));
    });
    const SEV_ORD = { critical:4, high:3, medium:2, low:1 };
    allCVEs.sort((a,b) => (SEV_ORD[b.sev]||0)-(SEV_ORD[a.sev]||0) || parseFloat(b.cvss)-parseFloat(a.cvss));
    const top5 = allCVEs.slice(0,5);
    if (!top5.length) { body.innerHTML = '<div style="color:#4a5568;font-size:11px;padding:12px 8px">No CVEs found</div>'; return; }
    body.innerHTML = top5.map((cve,i) =>
      `<div class="sct-row" style="animation-delay:${i*.06}s">
        <span class="sct-cve">${cve.id}</span>
        <span class="sct-sev sct-sev--${cve.sev}">${cve.sev.charAt(0).toUpperCase()+cve.sev.slice(1)}</span>
        <span class="sct-service">${cve.service}</span>
        <span class="sct-cvss">${cve.cvss}</span>
      </div>`).join('');
  }

  function _renderCVEBar(ch, risk) {
    _dc('soc-cvebar');
    const canvas = document.getElementById('ch-cve-service');
    if (!canvas) return;
    const ports   = risk?.hosts?.[0]?.ports || [];
    const svcCVEs = {};
    ports.forEach(p => {
      const svc = (p.service||'unknown').toUpperCase();
      const count = (p.cves||[]).length;
      if (count > 0) svcCVEs[svc] = (svcCVEs[svc]||0) + count;
    });
    const sorted  = Object.entries(svcCVEs).sort((a,b)=>b[1]-a[1]).slice(0,8);
    const fallback = ch?.cve_summary;
    const labels   = sorted.length ? sorted.map(s=>s[0]) : (fallback?.labels||[]);
    const data     = sorted.length ? sorted.map(s=>s[1]) : (fallback?.data||[]);
    if (!labels.length) return;
    const maxVal   = Math.max(...data, 1);
    const barColors = data.map(v => { const r=v/maxVal; return r>=.75?C.critical+'cc':r>=.5?C.high+'cc':r>=.25?C.medium+'cc':C.low+'cc'; });
    _charts['soc-cvebar'] = new Chart(canvas, {
      type: 'bar',
      data: { labels, datasets: [{ data, backgroundColor: barColors, borderColor: barColors.map(c=>c.slice(0,7)), borderWidth:1, borderRadius:4, borderSkipped:false }] },
      options: { responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false},tooltip:{backgroundColor:'#0f1623',borderColor:'#1e2a3a',borderWidth:1,titleColor:'#e6edf3',bodyColor:'#8b949e',padding:10}}, scales:{y:{beginAtZero:true,ticks:{color:'#4a5568',font:{size:10}},grid:{color:'#1a2030'}},x:{ticks:{color:'#6e7681',font:{size:10}},grid:{display:false}}}, animation:{duration:1200,easing:'easeOutQuart'} },
    });
  }

  function _renderActivityFeed(risk) {
    const el = document.getElementById('soc-activity-feed');
    if (!el) return;
    const host     = risk?.hosts?.[0] || {};
    const ports    = host.ports || [];
    const cveCount = ports.reduce((a,p) => a+(p.cves||[]).length, 0);
    const critPorts = ports.filter(p => p.risk?.level === 'critical');
    const ago = m => m < 60 ? `${m} minute${m===1?'':'s'} ago` : `${Math.floor(m/60)} hour${Math.floor(m/60)===1?'':'s'} ago`;
    const events = [
      { color:'green',  title:'Scan completed',                   sub:`${ports.length} services · ${cveCount} CVEs discovered`,                       time:ago(2)   },
      critPorts.length ? { color:'red',    title:'New critical vulnerability found', sub:`${critPorts[0]?.cves?.[0]?.cve_id||'CVE detected'} in ${(critPorts[0]?.service||'service').toUpperCase()}`, time:ago(10) } : null,
      cveCount > 0     ? { color:'orange', title:'New OSINT finding',                sub:'Potential data leak detected',                                           time:ago(60) } : null,
      ports.length > 0 ? { color:'blue',   title:'Service change detected',          sub:`New service detected on port ${ports[ports.length-1]?.port||80}`,        time:ago(180)} : null,
    ].filter(Boolean).slice(0,4);
    el.innerHTML = events.map((ev,i) =>
      `<div class="saf-item" style="animation-delay:${i*.08}s">
        <div class="saf-dot saf-dot--${ev.color}"></div>
        <div class="saf-body"><div class="saf-title">${ev.title}</div><div class="saf-sub">${ev.sub}</div></div>
        <div class="saf-time">${ev.time}</div>
      </div>`).join('');
  }

  function renderTrendCharts(d) {
    if (!d.labels?.length) return;
    _dc('trend'); _dc('cve-trend');
    const opts = { responsive:true, maintainAspectRatio:false, plugins:{legend:{labels:{color:'#8b949e',font:{size:10},boxWidth:10}}}, scales:{y:{beginAtZero:true,ticks:{color:'#8b949e'}},x:{ticks:{color:'#8b949e'}}} };
    const tc = document.getElementById('ch-trend');
    if (tc) _charts['trend'] = new Chart(tc, { type:'line', data:{ labels:d.labels, datasets:[{label:'Critical',data:d.risk_trend?.critical||[],borderColor:C.critical,backgroundColor:C.critical+'22',fill:true,tension:.3,pointRadius:2},{label:'High',data:d.risk_trend?.high||[],borderColor:C.high,backgroundColor:C.high+'22',fill:true,tension:.3,pointRadius:2}] }, options:opts });
    const cc = document.getElementById('ch-cve-trend');
    if (cc) _charts['cve-trend'] = new Chart(cc, { type:'line', data:{ labels:d.labels, datasets:[{label:'CVEs',data:d.cve_trend||[],borderColor:'#7f77dd',backgroundColor:'#7f77dd22',fill:true,tension:.3,pointRadius:2}] }, options:opts });
  }

  function _fmtDuration(secs) {
    const s=Math.round(secs), m=Math.floor(s/60), rem=s%60, h=Math.floor(m/60), remM=m%60;
    return h ? `${String(h).padStart(2,'0')}:${String(remM).padStart(2,'0')}:${String(rem).padStart(2,'0')}` : `00:${String(m).padStart(2,'0')}:${String(rem).padStart(2,'0')}`;
  }

  /* ══════════════════════════════════════════════════════════════
     SECTION C — OSINT FRAMEWORK GRAPH
     Completely isolated from Section B.
     Behaves like osintframework.com: starts collapsed, user
     clicks to progressively reveal intelligence layers.

     State machine:
       _osint.root     — raw data tree (full, never modified)
       _osint.expanded — Set of node IDs that are expanded
       _osint.svg/zoom — D3 references
       _osint.built    — has tree been initialized?

     Rendering:
       Only host node visible on init.
       Click host → ports appear (animated).
       Click port → service+version+CVEs appear.
       Click CVE  → patch+detail nodes appear.
       Each expansion is animated with enter transitions.
       Re-collapse hides children with exit transition.

     No global state shared with Chart.js section above.
  ══════════════════════════════════════════════════════════════ */

  // All OSINT state lives in this single isolated object
  const _osint = {
    built:    false,
    root:     null,    // raw tree data (immutable after build)
    expanded: new Set(), // node IDs currently expanded
    svg:      null,
    zoomG:    null,
    zoom:     null,
    idCtr:    0,
    riskData: null,    // last riskData passed to buildOsintTree
  };

  // ── Node appearance config ────────────────────────────────────
  const _O_COLOR = {
    host    : '#388bfd',
    port    : { critical:'#e24b4a', high:'#ef9f27', medium:'#f0c040', low:'#1d9e75', unknown:'#8b949e' },
    version : '#7f77dd',
    cve     : { critical:'#e24b4a', high:'#ef9f27', medium:'#f0c040', low:'#1d9e75', unknown:'#8b949e' },
    detail  : '#8b949e',
    detail_fix : '#1d9e75',
    patch      : '#1d9e75',
    attack     : '#e24b4a',
  };

  function _oColor(d) {
    const t  = d.data.type;
    const rl = d.data.riskLevel || 'unknown';
    if (t === 'host')    return _O_COLOR.host;
    if (t === 'port')    return _O_COLOR.port[rl]   || '#8b949e';
    if (t === 'version') return _O_COLOR.version;
    if (t === 'cve')     return _O_COLOR.cve[rl]    || '#8b949e';
    if (t === 'detail_fix' || t === 'patch') return _O_COLOR.patch;
    if (t === 'attack')  return _O_COLOR.attack;
    return _O_COLOR.detail;
  }

  function _oRadius(type) {
    // Small dots matching OSINT Framework visual style:
    // host = larger anchor node, all others = small terminal dots
    return {
      host:      14,   // root anchor — slightly larger
      port:       5,   // port dots — small, like OSINT Framework leaf dots
      version:    4,
      cve:        5,
      detail:     3.5,
      detail_fix: 3.5,
      patch:      4,
      attack:     5,
    }[type] || 4;
  }

  // ── Data builder ──────────────────────────────────────────────
  // Builds the FULL tree data structure but marks every non-root node
  // with _collapsed:true so the tree renders collapsed initially.
  function _buildOsintData(riskData) {
    const hosts = riskData?.hosts || [];
    const host  = hosts[0] || {};
    const ip    = host.ip || 'unknown';
    const rs    = host.risk_summary || {};

    const root = {
      id: `h-${++_osint.idCtr}`,
      name: ip,
      type: 'host',
      riskLevel: rs.overall || 'low',
      meta: { scan: 'Host', ports: (host.ports || []).length, risk: (rs.overall||'low').toUpperCase() },
      _collapsed: false,   // host starts visible
      _hasChildren: (host.ports || []).length > 0,
      children: [],
    };

    for (const port of (host.ports || [])) {
      const pnum  = port.port;
      const proto = port.protocol || 'tcp';
      const svc   = (port.service || 'unknown').toUpperCase();
      const rl    = port.risk?.level || 'low';
      const score = port.risk?.score || 0;
      const va    = port.version_analysis || {};
      const prod  = port.product || '';
      const ver   = port.version || '';
      const cves  = port.cves   || [];
      const patch = port.patch  || '';
      const chains= port.attack_chains || [];

      const portChildren = [];

      // Version node
      if (prod || ver) {
        const vStatus = va.status || 'unknown';
        const vColor  = { latest:'low', outdated:'medium', unsupported:'critical' }[vStatus] || 'low';
        portChildren.push({
          id: `v-${++_osint.idCtr}`,
          name: `${prod} ${ver}`.trim() || 'unknown version',
          type: 'version', riskLevel: vColor,
          meta: { status: vStatus, age: va.age_years ? va.age_years+'y' : '?', eol: va.eol_date || '' },
          _collapsed: true, _hasChildren: false, children: [],
        });
      }

      // CVE nodes
      for (const cve of cves.slice(0, 6)) {
        const cid   = cve.cve_id    || '?';
        const sev   = cve.severity  || 'unknown';
        const cvss  = cve.cvss_score || 0;
        const desc  = cve.description || '';
        const fix   = cve.patch       || '';
        const cveChildren = [
          { id:`cd-sev-${++_osint.idCtr}`, name:`${sev.toUpperCase()} · CVSS ${cvss}`, type:'detail', riskLevel:sev, meta:{ full:`Severity: ${sev.toUpperCase()}, CVSS: ${cvss}` }, _collapsed:true, _hasChildren:false, children:[] },
          { id:`cd-desc-${++_osint.idCtr}`, name:desc.length>46?desc.slice(0,46)+'…':desc||'No description', type:'detail', riskLevel:'low', meta:{ full:desc }, _collapsed:true, _hasChildren:false, children:[] },
          { id:`cd-fix-${++_osint.idCtr}`, name:fix?fix.length>46?fix.slice(0,46)+'…':fix:'No patch info', type:'detail_fix', riskLevel:'low', meta:{ full: fix || 'No patch guidance available.' }, _collapsed:true, _hasChildren:false, children:[] },
        ];
        portChildren.push({
          id: `cve-${++_osint.idCtr}`,
          name: cid, type: 'cve', riskLevel: sev,
          meta: { severity: sev.toUpperCase(), cvss, description: desc },
          _collapsed: true, _hasChildren: cveChildren.length > 0,
          children: cveChildren,
        });
      }

      // Attack chain nodes
      if (chains.length) {
        for (const chain of chains.slice(0,3)) {
          portChildren.push({
            id: `atk-${++_osint.idCtr}`,
            name: chain.name || 'Attack Chain',
            type: 'attack', riskLevel: 'critical',
            meta: { full: chain.narrative || '', score: chain.score || 0 },
            _collapsed: true, _hasChildren: false, children: [],
          });
        }
      }

      // Patch guidance node (if patch text available for the port)
      if (patch) {
        portChildren.push({
          id: `patch-${++_osint.idCtr}`,
          name: patch.length > 46 ? patch.slice(0,46)+'…' : patch,
          type: 'patch', riskLevel: 'low',
          meta: { full: patch },
          _collapsed: true, _hasChildren: false, children: [],
        });
      }

      root.children.push({
        id: `p-${++_osint.idCtr}`,
        name: `${pnum}/${proto} · ${svc}`,
        type: 'port', riskLevel: rl,
        meta: { port: pnum, service: svc, risk: rl.toUpperCase(), score, protocol: proto },
        _collapsed: true,   // ports start collapsed — OSINT Framework style
        _hasChildren: portChildren.length > 0,
        children: portChildren,
      });
    }

    return root;
  }

  // ── Tree renderer (D3) ────────────────────────────────────────
  // Renders only VISIBLE nodes (expanded path from root).
  // Uses enter/update/exit transitions for smooth OSINT-style reveals.
  function _renderOsintTree() {
    if (!_osint.root || !_osint.svg) return;

    const canvas = document.getElementById('osint-canvas');
    const W = canvas.clientWidth  || 900;
    const H = canvas.clientHeight || 560;

    // Build visible tree (only nodes reachable via non-collapsed path)
    function visibleChildren(n) {
      if (n._collapsed || !n.children || !n.children.length) return null;
      return n.children;
    }

    const hier   = d3.hierarchy(_osint.root, visibleChildren);
    const leaves = hier.leaves().length;
    const nodeH  = 22;    // vertical px per leaf — matches reference dense-but-readable spacing
    const treeH  = Math.max(H - 60, leaves * nodeH);
    const treeW  = Math.max(W  * 0.80, 700);
    const layout = d3.tree().size([treeH, treeW]);
    const treeRoot = layout(hier);

    // ── Links ────────────────────────────────────────────────────
    const linkGen = d3.linkHorizontal().x(d => d.y).y(d => d.x);
    const links   = d3.select('#osint-links')
      .selectAll('path')
      .data(treeRoot.links(), d => `${d.source.data.id}-${d.target.data.id}`);

    links.enter().append('path')
      .attr('d', linkGen)
      .attr('fill', 'none')
      .attr('stroke', '#2d3748')          // thin grey — matches OSINT Framework line color
      .attr('stroke-width', 0.8)
      .style('opacity', 0)
      .transition().duration(280)
      .style('opacity', 1);

    links.transition().duration(280)
      .attr('d', linkGen)
      .attr('stroke', '#2d3748');

    links.exit().transition().duration(200).style('opacity', 0).remove();

    // ── Nodes ─────────────────────────────────────────────────────
    const nodeData = d3.select('#osint-nodes')
      .selectAll('g.onode')
      .data(treeRoot.descendants(), d => d.data.id);

    // ENTER
    const enter = nodeData.enter().append('g')
      .attr('class', 'onode')
      .attr('transform', d => `translate(${d.y},${d.x})`)
      .style('opacity', 0)
      .style('cursor', d => d.data._hasChildren ? 'pointer' : 'default')
      .on('click',      (e, d) => { e.stopPropagation(); _osintToggleNode(d.data.id); })
      .on('mouseenter', (e, d) => _osintTip(e, d, true))
      .on('mouseleave', ()     => _osintTip(null, null, false))
      .on('touchstart', (e, d) => { e.preventDefault(); _osintTip(e.touches[0], d, true); }, { passive: false })
      .on('touchend',   (e, d) => { e.preventDefault(); _osintToggleNode(d.data.id); _osintTip(null, null, false); }, { passive: false });

    // Host outer ring glow
    enter.filter(d => d.data.type === 'host')
      .append('circle')
      .attr('r', d => _oRadius(d.data.type) + 9)
      .attr('fill', 'none')
      .attr('stroke', d => _oColor(d) + '44')
      .attr('stroke-width', 2);

    // ── Label (LEFT of the dot, right-aligned, white — matches OSINT Framework style)
    // All nodes: label sits to the LEFT of the circle, right-aligned text.
    // Host node: label sits to the right (it's the root on the left edge).
    enter.append('text')
      .attr('class', 'osint-label')
      .attr('x', d => {
        const r = _oRadius(d.data.type);
        // Host node sits on left side — label goes right of it
        if (d.data.type === 'host') return r + 10;
        // All other nodes: label sits LEFT of the dot, text right-aligned
        return -(r + 8);
      })
      .attr('dy', '0.35em')
      .attr('text-anchor', d => d.data.type === 'host' ? 'start' : 'end')
      .attr('font-size', d => ({
        host: 13, port: 12, version: 10, cve: 11,
        detail: 9, detail_fix: 9, patch: 9, attack: 11,
      }[d.data.type] || 10) + 'px')
      .attr('fill', '#e6edf3')
      .attr('font-weight', d => ['host','port','cve','attack'].includes(d.data.type) ? '600' : '400')
      .attr('letter-spacing', '0.01em')
      .text(d => {
        const max = {
          host:26, port:32, version:28, cve:20,
          detail:40, detail_fix:40, patch:40, attack:26,
        }[d.data.type] || 28;
        const s = String(d.data.name || '');
        return s.length > max ? s.slice(0, max) + '…' : s;
      });

    // ── Main dot (small filled circle — OSINT Framework style endpoint dot)
    // Sits at position (0,0) = the node position, on top of/after the label
    enter.append('circle')
      .attr('class', 'osint-dot')
      .attr('r', d => _oRadius(d.data.type))
      .attr('fill', d => _oColor(d))
      .attr('stroke', d => _oColor(d) + 'aa')
      .attr('stroke-width', d => d.data.type === 'host' ? 2.5 : 1.5)
      .attr('filter', d => d.data.type === 'host' ? 'url(#osint-glow)' : null)
      .style('cursor', d => d.data._hasChildren ? 'pointer' : 'default');

    // ── Expand indicator: small (+) badge on expandable dots
    enter.filter(d => d.data._hasChildren)
      .append('text')
      .attr('class', 'expand-sign')
      .attr('x', 0)
      .attr('y', '0.32em')
      .attr('text-anchor', 'middle')
      .attr('font-size', d => _oRadius(d.data.type) > 7 ? '8px' : '6px')
      .attr('fill', '#0f1623')
      .attr('font-weight', '800')
      .attr('pointer-events', 'none')
      .text(d => d.data._collapsed ? '+' : '−');

    // Animate enter
    enter.transition().duration(280)
      .attr('transform', d => `translate(${d.y},${d.x})`)
      .style('opacity', 1);

    // UPDATE — move existing nodes smoothly
    nodeData.transition().duration(280)
      .attr('transform', d => `translate(${d.y},${d.x})`);

    // Update expand sign +/−
    nodeData.select('.expand-sign')
      .text(d => d.data._collapsed ? '+' : '−');

    // Update dot fill on collapse/expand state change
    nodeData.select('.osint-dot')
      .attr('fill', d => _oColor(d))
      .attr('r',    d => _oRadius(d.data.type));

    // EXIT
    nodeData.exit().transition().duration(200).style('opacity', 0).remove();

    // ── Auto-fit viewport to visible tree on first build ─────────
    if (!_osint._fitted) {
      _osint._fitted = true;
      // Translate root to left side so labels fan out rightward (OSINT Framework layout)
      const padL = 160, padY = 30;
      const scaleX = (W - padL - 200) / treeW;
      const scaleY = (H - padY * 2) / treeH;
      const scale  = Math.min(scaleX, scaleY, 1.0);
      _osint.svg.call(
        _osint.zoom.transform,
        d3.zoomIdentity.translate(padL, (H - treeH * scale) / 2).scale(scale)
      );
    }
  }

  // ── Node toggle ───────────────────────────────────────────────
  // Toggles a node's _collapsed state and re-renders.
  // This is the CORE click-to-explore mechanism.
  function _osintToggleNode(nodeId) {
    function findAndToggle(node) {
      if (node.id === nodeId) {
        if (!node._hasChildren) return;
        node._collapsed = !node._collapsed;
        return true;
      }
      for (const child of (node.children || [])) {
        if (findAndToggle(child)) return true;
      }
    }
    if (_osint.root) {
      findAndToggle(_osint.root);
      _renderOsintTree();
    }
  }

  // ── Public OSINT API ──────────────────────────────────────────
  function isBuilt()   { return _osint.built; }
  function markStale() { _osint.built = false; _osint._fitted = false; }

  function clearOsint() {
    _osint.built    = false;
    _osint.root     = null;
    _osint.expanded.clear();
    _osint._fitted  = false;
    if (d3) {
      d3.select('#osint-links').selectAll('*').remove();
      d3.select('#osint-nodes').selectAll('*').remove();
    }
    const empty  = document.getElementById('osint-empty');
    const status = document.getElementById('osint-status');
    if (empty)  empty.style.display  = 'flex';
    if (status) status.textContent   = 'Run a scan first, then switch to this view.';
  }

  function buildOsintTree(riskData) {
    if (!riskData?.hosts?.length) return;

    _osint.built    = true;
    _osint.riskData = riskData;
    _osint._fitted  = false;
    _osint.idCtr    = 0;

    // Hide empty state
    const emptyEl = document.getElementById('osint-empty');
    if (emptyEl) emptyEl.style.display = 'none';

    // Build collapsed data tree
    _osint.root = _buildOsintData(riskData);

    // Init D3 SVG
    _osint.svg   = d3.select('#osint-svg');
    _osint.zoomG = d3.select('#osint-zoom-g');

    // Clear previous render
    d3.select('#osint-links').selectAll('*').remove();
    d3.select('#osint-nodes').selectAll('*').remove();

    // Set up zoom/pan
    _osint.zoom = d3.zoom()
      .scaleExtent([0.08, 5])
      .on('zoom', e => _osint.zoomG.attr('transform', e.transform));
    _osint.svg.call(_osint.zoom).on('dblclick.zoom', null);

    // Render collapsed tree (only host visible)
    _renderOsintTree();

    // Update status bar
    const host     = riskData.hosts[0] || {};
    const ports    = host.ports || [];
    const cveCount = ports.reduce((a,p) => a+(p.cves||[]).length, 0);
    const status   = document.getElementById('osint-status');
    if (status) status.textContent =
      `Host: ${host.ip||'?'} · ${ports.length} ports · ${cveCount} CVEs · Click any node to explore`;
  }

  function osintExpand() {
    // Expand all nodes one level at a time (breadth-first, 1 level)
    function exp(n) {
      if (n._hasChildren && n._collapsed) { n._collapsed = false; return; }
      (n.children || []).forEach(exp);
    }
    if (_osint.root) { exp(_osint.root); _renderOsintTree(); }
  }

  function osintCollapse() {
    // Collapse everything except the host root
    function col(n, depth) {
      if (depth > 0 && n._hasChildren) { n._collapsed = true; }
      (n.children || []).forEach(c => col(c, depth + 1));
    }
    if (_osint.root) { col(_osint.root, 0); _renderOsintTree(); }
  }

  function osintReset() {
    _osint._fitted = false;
    const canvas = document.getElementById('osint-canvas');
    const W = canvas.clientWidth, H = canvas.clientHeight;
    if (_osint.svg && _osint.zoom) {
      _osint.svg.transition().duration(500).call(
        _osint.zoom.transform,
        d3.zoomIdentity.translate(100, H / 2).scale(0.8)
      );
    }
  }

  // ── OSINT Tooltip ─────────────────────────────────────────────
  function _osintTip(e, d, show) {
    const tt = document.getElementById('osint-tip');
    if (!tt) return;
    if (!show) { tt.style.opacity = '0'; return; }

    const m    = d.data.meta || {};
    const ICON = { host:'🖥', port:'🔌', version:'📦', cve:'🛡', detail:'📄', detail_fix:'🔧', patch:'🩹', attack:'⚔' };
    const icon = ICON[d.data.type] || '●';
    const esc  = v => String(v||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const tr   = (k,v) => v ? `<div style="display:flex;gap:6px;margin-top:3px"><span style="color:#4a5568;font-size:10px;min-width:60px">${esc(k)}</span><span style="color:#8b949e;font-size:10px">${esc(v)}</span></div>` : '';

    let html = `<div style="font-weight:700;font-size:13px;margin-bottom:6px;color:#e6edf3">${icon} ${esc(d.data.name)}</div>`;

    if (d.data.type === 'host')    { html += tr('Ports', m.ports); html += tr('Risk', m.risk); }
    if (d.data.type === 'port')    { html += tr('Port', m.port); html += tr('Service', m.service); html += tr('Risk', m.risk); html += tr('Score', m.score+'/10'); }
    if (d.data.type === 'version') { html += tr('Status', m.status); html += tr('Age', m.age); if (m.eol) html += tr('EOL', m.eol); }
    if (d.data.type === 'cve')     { html += tr('Severity', m.severity); html += tr('CVSS', m.cvss); if (m.description) html += tr('Desc', m.description.slice(0,90)+'…'); }
    if (d.data.type === 'attack')  { html += tr('Score', m.score); if (m.full) html += `<div style="color:#8b949e;font-size:10px;margin-top:4px;line-height:1.5">${esc(m.full.slice(0,100)+'…')}</div>`; }
    if (['detail','detail_fix','patch'].includes(d.data.type) && m.full)
      html += `<div style="color:#8b949e;font-size:10px;margin-top:4px;line-height:1.5">${esc(m.full.slice(0,120))}</div>`;

    if (d.data._hasChildren) {
      html += `<div style="margin-top:6px;font-size:9px;color:#378add;border-top:1px solid #1e2a3a;padding-top:5px">${d.data._collapsed?'▶ Click to expand':'▼ Click to collapse'}</div>`;
    }

    tt.innerHTML = html;
    tt.style.opacity = '1';

    const x = e.clientX || e.pageX, y = e.clientY || e.pageY;
    const Ww = window.innerWidth, Wh = window.innerHeight;
    let l = x + 14, t = y - 12;
    if (l + 270 > Ww) l = x - 270;
    if (t + 200 > Wh) t = y - 180;
    tt.style.left = Math.max(4, l) + 'px';
    tt.style.top  = Math.max(4, t) + 'px';
  }

  /* ── Public API ─────────────────────────────────────────────── */
  return {
    // Radial dashboard
    destroyAll,
    renderDashboardCharts,
    renderTrendCharts,
    // OSINT tree
    isBuilt,
    markStale,
    clearOsint,
    buildOsintTree,
    osintExpand,
    osintCollapse,
    osintReset,
  };

})();
