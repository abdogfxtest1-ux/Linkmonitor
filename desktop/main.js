const { app, BrowserWindow, ipcMain, session, dialog, shell, powerSaveBlocker, webContents } = require('electron')
const fs = require('fs')
const path = require('path')
const ch = require('./channels')

// المواقع تشوف متصفح Chrome عادي مش Electron
app.userAgentFallback = app.userAgentFallback.replace(/\s(Electron|LinkMonitor|linkmonitor)\/\S+/g, '')

let win
const data = (...p) => path.join(app.getPath('userData'), ...p)
const logDir = () => { const d = data('logs'); fs.mkdirSync(d, { recursive: true }); return d }
const shotDir = () => { const d = path.join(app.getPath('pictures'), 'LinkMonitor'); fs.mkdirSync(d, { recursive: true }); return d }
const log = (s) => win && !win.isDestroyed() && win.webContents.send('log', s)

app.whenReady().then(() => {
  win = new BrowserWindow({
    width: 1280, height: 860, title: 'Link Monitor', autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), webviewTag: true, contextIsolation: true },
  })
  win.loadFile('index.html')
})
app.on('window-all-closed', () => { ch.shutdown(); app.quit() })
app.on('before-quit', () => ch.shutdown())

let blocker = null
ipcMain.handle('awake', (e, on) => {
  if (on && blocker === null) blocker = powerSaveBlocker.start('prevent-display-sleep')
  if (!on && blocker !== null) { powerSaveBlocker.stop(blocker); blocker = null }
})

ipcMain.handle('sites:get', () => { try { return JSON.parse(fs.readFileSync(data('sites.json'), 'utf8')) } catch (e) { return [] } })
ipcMain.handle('sites:set', (e, s) => fs.writeFileSync(data('sites.json'), JSON.stringify(s)))
ipcMain.handle('prefs:get', () => { try { return JSON.parse(fs.readFileSync(data('prefs.json'), 'utf8')) } catch (e) { return {} } })
ipcMain.handle('prefs:set', (e, p) => fs.writeFileSync(data('prefs.json'), JSON.stringify(p)))

ipcMain.handle('confs', () => ch.confs())
ipcMain.handle('confs:import', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openFile', 'multiSelections'], filters: [{ name: 'WireGuard', extensions: ['conf'] }] })
  for (const f of r.filePaths) fs.copyFileSync(f, path.join(ch.wgDir(), path.basename(f)))
  return r.filePaths.length
})
ipcMain.handle('confs:clear', () => { for (const f of ch.confs()) fs.unlinkSync(path.join(ch.wgDir(), f)) })
ipcMain.handle('open', (e, u) => shell.openExternal(u))
ipcMain.handle('shots:open', () => shell.openPath(shotDir()))

ipcMain.handle('activate', (e, c) => ch.activate(c, log, (pct, info) => e.sender.send('progress', pct, info)))

/** جلسة جديدة ونضيفة لكل فحص، بالـ proxy بتاع القناة، وبتبلّغ كود الاستجابة للصفحة الرئيسية. */
ipcMain.handle('prep', async (e, part, proxyRules) => {
  const ses = session.fromPartition(part)
  await ses.setProxy({ proxyRules })
  await ses.clearStorageData()
  ses.webRequest.onCompleted({ urls: ['*://*/*'] }, (d) => {
    if (d.resourceType !== 'mainFrame') return
    const h = Object.fromEntries(Object.entries(d.responseHeaders || {}).map(([k, v]) => [k.toLowerCase(), String(v)]))
    const cf = 'cf-mitigated' in h || (d.statusCode === 503 && /cloudflare/i.test(h.server || ''))
    e.sender.send('status', part, d.statusCode, d.statusCode === 403 || d.statusCode === 429 || cf)
  })
})
ipcMain.handle('release', async (e, part) => {
  const ses = session.fromPartition(part)
  ses.webRequest.onCompleted(null)
  await ses.clearStorageData().catch(() => {})
  ses.closeAllConnections().catch(() => {})
})

// لقطة الـ webview؛ لو capturePage بتاعه فشل (UnknownVizError على بعض الأجهزة) ناخد مكانه من الشباك نفسه
ipcMain.handle('shot', async (e, id, rect) => {
  for (const get of [() => webContents.fromId(id).capturePage(), () => win.webContents.capturePage(rect)]) {
    try { const img = await get(); if (!img.isEmpty()) return img.toDataURL() } catch (err) {}
  }
  return null
})

ipcMain.handle('records', () => {
  const out = []
  for (const f of fs.readdirSync(logDir()).filter((f) => f.endsWith('.jsonl')).sort()) {
    for (const l of fs.readFileSync(path.join(logDir(), f), 'utf8').split('\n')) { try { if (l) out.push(JSON.parse(l)) } catch (e) {} }
  }
  return out
})
ipcMain.handle('record', (e, o, png) => {
  if (png) {
    o.shot = `r${o.round}_${o.host}_${o.ts}.png`
    fs.writeFileSync(path.join(shotDir(), o.shot), Buffer.from(png.split(',')[1], 'base64'))
  }
  fs.appendFileSync(path.join(logDir(), o.ts.slice(0, 4) + '-' + o.ts.slice(4, 6) + '-' + o.ts.slice(6, 8) + '.jsonl'), JSON.stringify(o) + '\n')
  return o.shot || ''
})
ipcMain.handle('csv', async () => {
  const r = await dialog.showSaveDialog(win, { defaultPath: 'link-monitor.csv', filters: [{ name: 'CSV', extensions: ['csv'] }] })
  if (r.canceled || !r.filePath) return false
  const cols = ['ts', 'round', 'site', 'state', 'status', 'loadMs', 'channel', 'ip', 'detail', 'shot']
  const rows = []
  for (const f of fs.readdirSync(logDir()).filter((f) => f.endsWith('.jsonl')).sort()) {
    for (const l of fs.readFileSync(path.join(logDir(), f), 'utf8').split('\n')) {
      try { if (l) { const o = JSON.parse(l); rows.push(cols.map((c) => '"' + String(o[c] ?? '').replace(/"/g, '""') + '"').join(',')) } } catch (e) {}
    }
  }
  fs.writeFileSync(r.filePath, '﻿' + cols.join(',') + '\n' + rows.join('\n') + '\n')
  return true
})
