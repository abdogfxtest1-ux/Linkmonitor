const { contextBridge, ipcRenderer } = require('electron')

const call = (c) => (...a) => ipcRenderer.invoke(c, ...a)
contextBridge.exposeInMainWorld('lm', {
  sitesGet: call('sites:get'), sitesSet: call('sites:set'),
  prefsGet: call('prefs:get'), prefsSet: call('prefs:set'),
  confs: call('confs'), confsImport: call('confs:import'), confsClear: call('confs:clear'),
  activate: call('activate'), prep: call('prep'), release: call('release'),
  records: call('records'), shot: call('shot'), record: call('record'), csv: call('csv'),
  open: call('open'), shotsOpen: call('shots:open'), awake: call('awake'),
  on: (c, f) => ipcRenderer.on(c, (e, ...a) => f(...a)),
})
