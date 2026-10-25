const $ = (id) => document.getElementById(id)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const host = (u) => u.replace(/^https?:\/\//, '').split('/')[0]
const idx = (s) => ({ success: 0, blocked: 2, proxy: 3 }[s] ?? 1)
const stamp = () => { const d = new Date(), p = (n) => String(n).padStart(2, '0'); return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}` }

const MAX = 6
const sites = []
const cards = {}
const cnt = {}       // success, failed, blocked, proxy
const info = {}
const active = new Set()
const statusBy = {}  // partition → {code, blocked}
let looping = false
let round = 0

function log(s) {
  const l = $('log')
  l.textContent = new Date().toLocaleTimeString('en-GB') + '  ' + s + '\n' + l.textContent.split('\n').slice(0, 200).join('\n')
}
window.lm.on('log', log)
window.lm.on('status', (part, code, blocked) => { statusBy[part] = { code, blocked } })
window.lm.on('progress', (pct, bi) => { $('status').textContent = `جولة ${round} • Tor يتصل (${bi})... ${pct}%` })

function refresh(u, tick) {
  const c = cnt[u] || [0, 0, 0, 0], tot = c[0] + c[1]
  const up = tot ? (c[0] * 100 / tot).toFixed(1) + '%' : '—'
  const on = active.has(u)
  const k = cards[u]; if (!k) return
  k.t.innerHTML = ''
  const b = document.createElement('b'); b.textContent = `${on ? '🟢' : '⚪'} ${host(u)}   Uptime ${up}`
  // العدادات في bdi عشان الأرقام والرموز متتلخبطش جوه السطر العربي
  const n = document.createElement('span'); n.style.cssText = 'direction:ltr;unicode-bidi:isolate;display:inline-block'
  n.textContent = `✓${c[0]}  ✗${c[1]}  ⛔${c[2]}  ⚠${c[3]}` + (tick != null ? `   ⏱ ${tick}` : '')
  k.t.append(b, '\n', n, '\n' + (info[u] || 'متوقف'))
  k.toggle.textContent = on ? '■ Stop' : '▶ Start'
}

function addSite(raw, save = true) {
  let u = raw.trim(); if (!u) return
  if (!/^https?:\/\//.test(u)) u = 'https://' + u
  if (sites.includes(u)) return
  if (sites.length >= MAX) { alert(`الحد الأقصى ${MAX} مواقع`); return }
  sites.push(u); cnt[u] = cnt[u] || [0, 0, 0, 0]
  const el = document.createElement('div'); el.className = 'card'
  const t = document.createElement('div'); t.className = 't'; t.title = 'اضغط للتكبير'
  const box = document.createElement('div'); box.className = 'box'
  const a = document.createElement('div'); a.className = 'a'
  const toggle = document.createElement('button')
  const del = document.createElement('button'); del.textContent = '✕ حذف'
  toggle.onclick = () => (active.has(u) ? stopSite(u) : startSite(u))
  del.onclick = () => removeSite(u)
  t.onclick = () => el.classList.toggle('big')
  a.append(toggle, del); el.append(t, box, a); $('cards').append(el)
  cards[u] = { el, t, box, toggle, wv: null }
  refresh(u)
  if (save) window.lm.sitesSet(sites)
}

function removeSite(u) {
  stopSite(u)
  cards[u]?.el.remove(); delete cards[u]
  sites.splice(sites.indexOf(u), 1); window.lm.sitesSet(sites)
}

function startSite(u) {
  if (active.has(u)) return
  active.add(u); info[u] = '⏳ بانتظار الجولة'; refresh(u)
  if (!looping) loop()
}

function stopSite(u) {
  if (!active.has(u)) return
  active.delete(u)
  const k = cards[u]; if (k && k.wv) { k.wv.remove(); k.wv = null }
  info[u] = 'متوقف'; refresh(u)
}

async function loop() {
  looping = true
  window.lm.awake(true)
  try {
    while (active.size) {
      round++
      const confs = await window.lm.confs()
      const ccs = $('tor').checked ? $('cc').value.split(',').map((s) => s.trim().toLowerCase()).filter((s) => s.length === 2) : []
      const chans = []
      if ($('direct').checked || (!confs.length && !ccs.length)) chans.push({ name: 'direct' })
      confs.forEach((f) => chans.push({ name: f.replace(/\.conf$/, ''), file: f }))
      ccs.forEach((c) => chans.push({ name: 'tor-' + c, cc: c }))
      const chn = chans[(round - 1) % chans.length]
      $('status').textContent = `جولة ${round} • بيجهّز ${chn.name}...`
      const r = await window.lm.activate(chn)
      const ip = r.ip ? `${r.ip.ip} (${r.ip.country})` : ''
      const snap = [...active]
      if (r.err) {
        for (const u of snap) if (active.has(u)) { info[u] = `⚠ فشل ${chn.name}: ${r.err}`; await record(u, 'proxy', 0, 0, r.err, chn.name, ip, null) }
        await sleep(2000); continue
      }
      $('status').textContent = `جولة ${round} • ${chn.name} • ${ip || 'IP؟'} • جلسات: ${active.size}`
      for (const u of snap) { info[u] = `جولة ${round} • ${chn.name} • ${ip || 'IP؟'}`; refresh(u) }
      const dur = Math.min(600, Math.max(5, +$('dur').value || 30))
      await Promise.all(snap.map(async (u, i) => {
        try {
          const res = await probe(u, `lm-${i}-${round}`, r.proxy, dur)
          if (res && active.has(u)) await record(u, res.state, res.status, res.ms, res.detail, chn.name, ip, res.shot)
        } catch (e) { log(`خطأ ${host(u)}: ${e.message}`) }
      }))
      await sleep(2000)
    }
  } finally {
    looping = false
    window.lm.awake(false)
    $('status').textContent = 'متوقف'
  }
}

/** فحص موقع واحد في webview جديد ونضيف ظاهر في الكارت. يرجّع null لو الجلسة اتوقفت. */
async function probe(u, part, proxy, dur) {
  const k = cards[u]; if (!k) return null
  await window.lm.prep(part, proxy)
  if (!active.has(u)) return null
  const wv = document.createElement('webview')
  wv.setAttribute('partition', part)
  wv.setAttribute('src', u)
  if (k.wv) k.wv.remove()
  k.wv = wv
  let err = null, gone = false, retried = false, loaded
  const done = new Promise((r) => (loaded = r))
  wv.addEventListener('did-fail-load', (e) => {
    if (!e.isMainFrame || e.errorCode === -3) return // -3 = اتلغى (redirect مثلاً)
    // أول طلب بعد تبديل القناة ممكن يقع بـ NETWORK_CHANGED؛ ده مش عطل في الموقع فنعيد مرة
    if (!retried && /NETWORK_CHANGED/.test(e.errorDescription)) { retried = true; setTimeout(() => wv.reload(), 800); return }
    err = `${e.errorCode} ${e.errorDescription}`; loaded()
  })
  wv.addEventListener('did-finish-load', () => loaded())
  wv.addEventListener('render-process-gone', () => { gone = true })
  const t0 = performance.now()
  k.box.append(wv)
  const ok = await Promise.race([done.then(() => true), sleep(15000).then(() => false)])
  const ms = Math.round(performance.now() - t0)
  const st = statusBy[part] || { code: 0, blocked: false }
  const shot = async () => {
    const r = wv.getBoundingClientRect()
    const rect = { x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width), height: Math.round(r.height) }
    try { return await window.lm.shot(wv.getWebContentsId(), rect) } catch (e) { return null }
  }
  const finish = async (res) => {
    if (k.wv === wv) { wv.remove(); k.wv = null }
    delete statusBy[part]; window.lm.release(part)
    return res
  }
  const bad = async (state, detail) => finish({ state, status: st.code, ms, detail, shot: active.has(u) ? await shot() : null })
  if (!active.has(u)) return finish(null)
  if (!ok) return bad('timeout', '15s')
  if (err) return bad('http', err)
  if (st.code >= 400) return bad(st.blocked ? 'blocked' : 'http', 'HTTP ' + st.code)
  err = null
  for (let i = 1; i <= dur; i++) {
    await sleep(1000)
    if (!active.has(u)) return finish(null)
    refresh(u, dur - i)
    if (gone) return bad('mid', 'renderer crash')
    if (err) return bad('mid', err)
    if (i % 5 === 0) {
      const n = await wv.executeJavaScript("(function(){var b=document.body;if(!b)return 0;return (b.innerText||'').trim().length+b.querySelectorAll('img,canvas,video,svg,iframe').length})()").catch(() => -1)
      if (n === 0) return bad('mid', 'blank page')
    }
  }
  return finish({ state: 'success', status: st.code || 200, ms, detail: '', shot: null })
}

async function record(u, state, status, ms, detail, channel, ip, png) {
  cnt[u] = cnt[u] || [0, 0, 0, 0]; cnt[u][idx(state)]++
  await window.lm.record({ ts: stamp(), round, site: u, host: host(u), state, status, loadMs: ms, detail, channel, ip }, png)
  log(`R${round} ${host(u)} [${channel}] → ${state} ${detail}`)
  refresh(u)
}

async function updateImp() { $('imp').textContent = `استيراد VPN (${(await window.lm.confs()).length})` }
async function savePrefs() { window.lm.prefsSet({ dur: $('dur').value, direct: $('direct').checked, tor: $('tor').checked, cc: $('cc').value }) }

$('add').onclick = () => { addSite($('url').value); $('url').value = '' }
$('url').onkeydown = (e) => { if (e.key === 'Enter') $('add').click() }
$('startAll').onclick = () => { if (!sites.length) alert('ضيف لينك الأول'); sites.forEach(startSite) }
$('stopAll').onclick = () => [...active].forEach(stopSite)
$('imp').onclick = async () => { const n = await window.lm.confsImport(); await updateImp(); if (n) log(`تم استيراد ${n} ملف`) }
$('clr').onclick = async () => { if (looping) return alert('وقّف الجلسات الأول'); if (confirm('تمسح كل ملفات الـ VPN؟')) { await window.lm.confsClear(); updateImp() } }
$('help').onclick = () => $('dlg').showModal()
$('close').onclick = () => $('dlg').close()
$('proton').onclick = () => window.lm.open('https://account.protonvpn.com/downloads')
$('csv').onclick = () => window.lm.csv()
$('shots').onclick = () => window.lm.shotsOpen()
for (const id of ['dur', 'direct', 'tor', 'cc']) $(id).onchange = savePrefs

;(async () => {
  const p = await window.lm.prefsGet()
  if (p.dur) $('dur').value = p.dur
  if (p.direct != null) $('direct').checked = p.direct
  if (p.tor != null) $('tor').checked = p.tor
  if (p.cc) $('cc').value = p.cc
  for (const o of await window.lm.records()) { cnt[o.site] = cnt[o.site] || [0, 0, 0, 0]; cnt[o.site][idx(o.state)]++ }
  for (const s of await window.lm.sitesGet()) addSite(s, false)
  updateImp()
})()
