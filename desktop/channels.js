// مصادر الـ IP: اتصال مباشر، WireGuard (عن طريق wireproxy بدون صلاحيات أدمن)، و Tor بالـ bridges.
const { app, session } = require('electron')
const { spawn } = require('child_process')
const fs = require('fs')
const net = require('net')
const path = require('path')

const vendor = app.isPackaged ? path.join(process.resourcesPath, 'vendor') : path.join(__dirname, 'vendor')
const data = (...p) => path.join(app.getPath('userData'), ...p)
const fwd = (p) => p.replace(/\\/g, '/')
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function freePort() {
  return new Promise((res, rej) => {
    const s = net.createServer()
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)) })
    s.on('error', rej)
  })
}

let chk = 0
/** يرجّع {ip, country} أو null. بيجرب أكتر من خدمة عن طريق نفس الـ proxy. */
async function ipInfo(proxyRules, timeoutMs = 10000) {
  const ses = session.fromPartition('lm-chk-' + (++chk))
  await ses.setProxy({ proxyRules })
  const get = async (u) => {
    const r = await ses.fetch(u, { signal: AbortSignal.timeout(timeoutMs), cache: 'no-store' })
    if (!r.ok) throw new Error('HTTP ' + r.status)
    return r.text()
  }
  const tries = [
    async () => {
      const kv = Object.fromEntries((await get('https://www.cloudflare.com/cdn-cgi/trace')).split('\n').map((l) => l.split('=')))
      // Cloudflare بيكتب T1 لأي Tor بدل الدولة، فنسيبها للخدمة اللي بعدها
      return kv.ip && kv.loc !== 'T1' ? { ip: kv.ip, country: kv.loc || '?' } : null
    },
    async () => { const j = JSON.parse(await get('https://ipwho.is/')); return j.success === false ? null : { ip: j.ip, country: j.country || '?' } },
    async () => { const j = JSON.parse(await get('https://ipapi.co/json/')); return j.ip ? { ip: j.ip, country: j.country_name || '?' } : null },
  ]
  try {
    for (const t of tries) { try { const r = await t(); if (r) return r } catch (e) {} }
    return null
  } finally { ses.closeAllConnections().catch(() => {}) }
}

// ---------------- WireGuard ----------------
const wgDir = () => { const d = data('wg'); fs.mkdirSync(d, { recursive: true }); return d }
const confs = () => fs.readdirSync(wgDir()).filter((f) => f.endsWith('.conf')).sort()
// بورتات WireGuard اللي سيرفرات Proton بتسمع عليها؛ لو المزوّد قافل بورت نجرب غيره
const ALT_PORTS = [51820, 443, 4500, 500, 1224, 88]
// ملف كل بوراته فشلت مش بنعيد تجربته قبل نص ساعة، عشان ميضيّعش دقيقة كل جولة
const DEAD_MS = 30 * 60 * 1000
const dead = {}
// المزوّد في مصر بيقرر لكل اتصال UDP جديد: يا يعدّي الـ handshake في أول ثواني يا يقفله على طول.
// فبنجرب اتصالات جديدة كتير قصيرة، واللي يشتغل بنسيبه مفتوح بين الجولات بدل ما نبدأ من الأول.
const ATTEMPTS = 8
const MAX_OPEN = 4
const tunnels = {} // name → {proc, proxy, used}

function close(name) { const t = tunnels[name]; if (t) { try { t.proc.kill() } catch (e) {} delete tunnels[name] } }
function wgDown() { for (const n of Object.keys(tunnels)) close(n) }

/** يشغّل ملف WireGuard كـ SOCKS proxy محلي. يرجّع {proxy, ip} أو {err}. */
async function wgUp(name, log) {
  if (tunnels[name]) {
    const inf = await ipInfo(tunnels[name].proxy, 10000)
    if (inf) { tunnels[name].used = Date.now(); return { proxy: tunnels[name].proxy, ip: inf } }
    close(name)
  }
  if (dead[name] && Date.now() - dead[name] < DEAD_MS) return { err: 'السيرفر مردّش من شوية، هيتجرب تاني بعد نص ساعة' }
  const file = path.join(wgDir(), name)
  const txt = fs.readFileSync(file, 'utf8')
  const m = txt.match(/^\s*Endpoint\s*=\s*(\S+):(\d+)\s*$/im)
  if (!m) return { err: 'الملف مفيهوش Endpoint' }
  const ports = [...new Set([+m[2], ...ALT_PORTS])]
  const tmp = data('wp'); fs.mkdirSync(tmp, { recursive: true })
  const base = name.replace(/\.conf$/, '')
  for (let i = 0; i < ATTEMPTS; i++) {
    const p = ports[i % ports.length]
    const conf = txt.replace(m[0], m[0].replace(/:\d+(\s*)$/, ':' + p + '$1'))
    const port = await freePort()
    fs.writeFileSync(path.join(tmp, base + '.wg.conf'), conf)
    fs.writeFileSync(path.join(tmp, base + '.wp.conf'), `WGConfig = ${fwd(path.join(tmp, base + '.wg.conf'))}\n\n[Socks5]\nBindAddress = 127.0.0.1:${port}\n`)
    const proc = spawn(path.join(vendor, 'wireproxy.exe'), ['-c', path.join(tmp, base + '.wp.conf')], { windowsHide: true })
    proc.on('error', (e) => log('wireproxy: ' + e.message))
    await sleep(1000)
    const proxy = `socks5://127.0.0.1:${port}`
    // الـ handshake الناجح بيخلص في أقل من 7 ثواني، وأكتر من كده مبيفرقش
    const inf = await ipInfo(proxy, 9000)
    if (inf) {
      // البورت اللي اشتغل يتحفظ في الملف نفسه، فالمرة الجاية يبدأ بيه على طول
      if (p !== +m[2]) { fs.writeFileSync(file, conf); log(`${name}: اشتغل على بورت ${p} واتحفظ`) }
      delete dead[name]
      tunnels[name] = { proc, proxy, used: Date.now() }
      const open = Object.entries(tunnels).sort((a, b) => a[1].used - b[1].used)
      while (open.length > MAX_OPEN) close(open.shift()[0])
      return { proxy, ip: inf }
    }
    try { proc.kill() } catch (e) {}
  }
  dead[name] = Date.now()
  return { err: `السيرفر مردّش بعد ${ATTEMPTS} محاولات (بورتات ${ports.join(',')})` }
}

// ---------------- Tor ----------------
const tor = { proc: null, socks: 0, ctl: 0, pct: 0, ready: false, bridgeInfo: '', ctlSock: null }
const torRoot = () => path.join(vendor, 'tor')

async function moat(p, body) {
  const r = await fetch('https://bridges.torproject.org/moat/circumvention/' + p, {
    method: 'POST', headers: { 'Content-Type': 'application/vnd.api+json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(10000),
  })
  return r.json()
}

/** Bridges جديدة من Tor نفسه حسب دولة الاتصال، ولو فشل آخر نسخة محفوظة، ولو مفيش اللي جاية مع Tor. */
async function bridges(ptConf) {
  const cache = data('bridges.txt')
  let got = []
  try {
    const s = await moat('settings', { transports: ['obfs4', 'snowflake'] })
    for (const x of s.settings || []) got.push(...((x.bridges && x.bridges.bridge_strings) || []))
    if (!got.length) { const b = await moat('builtin', {}); got.push(...(b.obfs4 || []), ...(b.snowflake || [])) }
  } catch (e) {}
  got = [...new Set(got.filter((l) => /^(obfs4|snowflake) /.test(l)))]
  if (got.length) { fs.writeFileSync(cache, got.join('\n')); tor.bridgeInfo = 'bridges محدّثة'; return got }
  try { const old = fs.readFileSync(cache, 'utf8').split('\n').filter(Boolean); if (old.length) { tor.bridgeInfo = 'bridges محفوظة'; return old } } catch (e) {}
  tor.bridgeInfo = 'bridges مدمجة'
  return [...(ptConf.bridges.obfs4 || []), ...(ptConf.bridges.snowflake || [])]
}

async function torStart(log) {
  if (tor.proc) return
  const root = torRoot()
  const ptDir = path.join(root, 'tor', 'pluggable_transports')
  const ptConf = JSON.parse(fs.readFileSync(path.join(ptDir, 'pt_config.json'), 'utf8'))
  const list = await bridges(ptConf)
  tor.socks = await freePort(); tor.ctl = await freePort()
  const dd = data('tor-data'); fs.mkdirSync(dd, { recursive: true })
  const plug = (k) => ptConf.pluggableTransports[k].replace(/\$\{pt_path\}/g, fwd(ptDir) + '/')
  const rc = [
    `DataDirectory ${fwd(dd)}`,
    `SocksPort 127.0.0.1:${tor.socks}`,
    `ControlPort 127.0.0.1:${tor.ctl}`,
    'CookieAuthentication 1',
    `GeoIPFile ${fwd(path.join(root, 'data', 'geoip'))}`,
    `GeoIPv6File ${fwd(path.join(root, 'data', 'geoip6'))}`,
    'UseBridges 1',
    plug('lyrebird'),
    plug('snowflake'),
    ...list.map((b) => 'Bridge ' + b),
  ].join('\n') + '\n'
  fs.writeFileSync(path.join(dd, 'torrc'), rc)
  tor.pct = 0; tor.ready = false
  tor.proc = spawn(path.join(root, 'tor', 'tor.exe'), ['-f', path.join(dd, 'torrc')], { windowsHide: true, cwd: dd })
  tor.proc.stdout.on('data', (b) => {
    for (const m of b.toString().matchAll(/Bootstrapped (\d+)%/g)) tor.pct = Math.max(tor.pct, +m[1])
    if (tor.pct >= 100) tor.ready = true
  })
  tor.proc.on('exit', (c) => { log('Tor اتقفل (' + c + ')'); tor.proc = null; tor.ready = false; tor.ctlSock = null })
  tor.proc.on('error', (e) => log('Tor: ' + e.message))
}

function torStop() { if (tor.proc) { try { tor.proc.kill() } catch (e) {} } tor.proc = null; tor.ready = false; tor.ctlSock = null }

/** أمر واحد على الـ ControlPort، يرجّع الرد كله. */
async function ctlCmd(cmd) {
  try {
    if (!tor.ctlSock) {
      const s = net.connect(tor.ctl, '127.0.0.1')
      await new Promise((r, j) => { s.once('connect', r); s.once('error', j) })
      s.setEncoding('utf8')
      s.on('error', () => {})
      s.on('close', () => { if (tor.ctlSock === s) tor.ctlSock = null })
      const cookie = fs.readFileSync(path.join(data('tor-data'), 'control_auth_cookie')).toString('hex')
      const a = await send(s, 'AUTHENTICATE ' + cookie)
      if (!a.startsWith('250')) throw new Error('auth: ' + a)
      tor.ctlSock = s
    }
    const r = await send(tor.ctlSock, cmd)
    if (!r.startsWith('250')) throw new Error(r)
    return r
  } catch (e) { tor.ctlSock = null; throw e }
}
function send(s, cmd) {
  return new Promise((res, rej) => {
    let buf = ''
    const t = setTimeout(() => { s.off('data', on); rej(new Error('timeout')) }, 10000)
    const on = (d) => {
      buf += d
      // الرد بيخلص بسطر "كود + مسافة"، زي "250 OK"
      const lines = buf.split(/\r?\n/)
      if (buf.endsWith('\n') && /^\d{3} /.test(lines[lines.length - 2] || '')) { clearTimeout(t); s.off('data', on); res(buf.trim()) }
    }
    s.on('data', on)
    s.write(cmd + '\r\n')
  })
}

/** يجهّز Tor بدولة الخروج المطلوبة. onProgress بتاخد النسبة. */
async function torUp(cc, log, onProgress) {
  await torStart(log)
  const t0 = Date.now()
  while (!tor.ready && Date.now() - t0 < 240000) {
    if (!tor.proc) return { err: 'Tor مش راضي يشتغل' }
    onProgress(tor.pct, tor.bridgeInfo); await sleep(1000)
  }
  if (!tor.ready) return { err: `Tor وقف عند ${tor.pct}% (${tor.bridgeInfo})` }
  const proxy = `socks5://127.0.0.1:${tor.socks}`
  let inf = null
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      if (attempt === 1) await ctlCmd(`SETCONF ExitNodes={${cc}} StrictNodes=1`)
      // الدوائر القديمة مش بتلتزم بالدولة الجديدة، فنقفلها كلها قبل NEWNYM
      const circs = (await ctlCmd('GETINFO circuit-status')).split(/\r?\n/).map((l) => l.match(/^(\d+) [A-Z_]+/)).filter(Boolean)
      for (const m of circs) await ctlCmd('CLOSECIRCUIT ' + m[1]).catch(() => {})
      await ctlCmd('SIGNAL NEWNYM')
    } catch (e) { return { err: 'Tor مش قابل يغيّر الدولة: ' + e.message } }
    // Tor مش بيقبل NEWNYM أكتر من مرة كل 10 ثواني
    await sleep(attempt === 1 ? 5000 : 11000)
    inf = null
    for (let i = 0; i < 3 && !inf; i++) { inf = await ipInfo(proxy, 20000); if (!inf) await sleep(3000) }
    if (!inf) return { proxy, ip: { ip: 'Tor-' + cc, country: '?' } }
    // الدولة من قاعدة Tor نفسها، عشان خدمات الـ IP ساعات بتختلف على مخارج Tor
    try { const m = (await ctlCmd('GETINFO ip-to-country/' + inf.ip)).match(/=(\w\w)/); if (m) inf.country = m[1].toUpperCase() } catch (e) {}
    if (inf.country.toLowerCase() === cc) break
    log(`Tor طلع من ${inf.country} بدل ${cc.toUpperCase()}، بيعيد`)
  }
  return { proxy, ip: inf }
}

/** يفعّل القناة ويرجّع {proxy, ip} أو {err}. */
async function activate(ch, log, onProgress) {
  // الأنفاق المفتوحة بتفضل شغالة في الجولات التانية؛ كل قناة ليها proxy لوحدها فمش بتأثر على بعض
  if (ch.cc) return torUp(ch.cc, log, onProgress)
  if (ch.file) return wgUp(ch.file, log)
  return { proxy: 'direct://', ip: await ipInfo('direct://') }
}

function shutdown() { wgDown(); torStop() }

module.exports = { activate, confs, wgDir, shutdown, ipInfo }
