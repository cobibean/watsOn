import { app, BrowserWindow, Menu, dialog, shell } from 'electron'
import { startServer } from '../server/index.js'

let mainWindow
let localServer

async function ensureLocalServer() {
  if (localServer) return localServer

  localServer = await startServer({
    isDev: false,
    log: false,
    port: 0,
  })

  return localServer
}

async function createMainWindow() {
  const server = await ensureLocalServer()

  mainWindow = new BrowserWindow({
    backgroundColor: '#f7f7f2',
    height: 820,
    minHeight: 680,
    minWidth: 1040,
    show: false,
    title: 'watsOn',
    titleBarStyle: 'default',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
    width: 1280,
  })

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show()
  })

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    void shell.openExternal(url)
    return { action: 'deny' }
  })

  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (url.startsWith(server.url)) return
    event.preventDefault()
    void shell.openExternal(url)
  })

  await mainWindow.loadURL(server.url)
}

function installMenu() {
  const template = [
    {
      label: 'watsOn',
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' },
      ],
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' },
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { type: 'separator' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
      ],
    },
    {
      label: 'Window',
      submenu: [{ role: 'minimize' }, { role: 'zoom' }, { role: 'front' }],
    },
  ]

  Menu.setApplicationMenu(Menu.buildFromTemplate(template))
}

app.setName('watsOn')

app.whenReady().then(async () => {
  installMenu()
  await createMainWindow()
}).catch((error) => {
  console.error(error)
  dialog.showErrorBox('watsOn failed to start', error.message)
  app.exit(1)
})

app.on('activate', async () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    await createMainWindow()
  }
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', async (event) => {
  if (!localServer) return

  event.preventDefault()
  const server = localServer
  localServer = undefined

  try {
    await server.close()
  } catch (error) {
    console.error(error)
  } finally {
    app.exit(0)
  }
})

process.on('uncaughtException', (error) => {
  console.error(error)
  dialog.showErrorBox('watsOn failed to start', error.message)
  app.exit(1)
})
