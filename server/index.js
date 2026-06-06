import { existsSync } from 'node:fs'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import cors from 'cors'
import express from 'express'
import { askAssistant, streamAssistant } from './assistant.js'
import { scanServices, stopProcess } from './scanner.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const defaultRootDir = join(__dirname, '..')

export function createApp({
  getApiPort = () => Number(process.env.PORT ?? 4141),
  isDev = process.argv.includes('--dev') || process.env.NODE_ENV === 'development',
  rootDir = defaultRootDir,
  uiPort = Number(process.env.WATSON_UI_PORT ?? 5173),
} = {}) {
  loadLocalEnv(rootDir)

  const app = express()
  const distDir = join(rootDir, 'dist')

  app.use(cors({ origin: true }))
  app.use(express.json({ limit: '32kb' }))
  app.use((error, _request, response, next) => {
    if (error instanceof SyntaxError && 'body' in error) {
      response.status(400).json({ error: 'Request body must be valid JSON.' })
      return
    }
    next(error)
  })

  app.get('/api/health', (_request, response) => {
    response.json({ ok: true, name: 'watsOn', port: getApiPort() })
  })

  app.get('/api/scan', async (_request, response) => {
    try {
      const payload = await scanServices({
        appPorts: [getApiPort(), isDev ? uiPort : undefined].filter(Boolean),
      })
      response.json(payload)
    } catch (error) {
      response.status(500).json({
        error: error instanceof Error ? error.message : 'Unable to scan services',
      })
    }
  })

  app.get('/api/config', (_request, response) => {
    response.json({
      hasOpenRouterKey: Boolean(process.env.OPENROUTER_API_KEY),
      model: process.env.OPENROUTER_MODEL || 'openrouter/auto',
    })
  })

  app.post('/api/ask', async (request, response) => {
    const question = String(request.body?.question ?? '').trim()
    const model = String(request.body?.model ?? process.env.OPENROUTER_MODEL ?? '').trim()
    const service = request.body?.service

    if (!question) {
      response.status(400).json({ error: 'A question is required.' })
      return
    }

    if (!service || typeof service !== 'object') {
      response.status(400).json({ error: 'Selected service evidence is required.' })
      return
    }

    try {
      const answer = await askAssistant({ model, question, service })
      response.json(answer)
    } catch (error) {
      response.status(error.statusCode ?? 500).json({
        error: error instanceof Error ? error.message : 'Unable to ask OpenRouter',
      })
    }
  })

  app.post('/api/ask/stream', async (request, response) => {
    const question = String(request.body?.question ?? '').trim()
    const model = String(request.body?.model ?? process.env.OPENROUTER_MODEL ?? '').trim()
    const service = request.body?.service

    if (!question) {
      response.status(400).json({ error: 'A question is required.' })
      return
    }

    if (!service || typeof service !== 'object') {
      response.status(400).json({ error: 'Selected service evidence is required.' })
      return
    }

    try {
      await streamAssistant({
        model,
        question,
        service,
        onReady: () => {
          response.writeHead(200, {
            'Cache-Control': 'no-cache, no-transform',
            'Content-Type': 'text/plain; charset=utf-8',
            'X-Accel-Buffering': 'no',
          })
        },
        onToken: (token) => response.write(token),
      })
      response.end()
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to ask OpenRouter'
      const statusCode =
        error && typeof error === 'object' && 'statusCode' in error
          ? Number(error.statusCode)
          : 500

      if (response.headersSent) {
        response.write(`\n${message}`)
        response.end()
        return
      }

      response.status(Number.isInteger(statusCode) ? statusCode : 500).json({
        error: message,
      })
    }
  })

  app.post('/api/stop', async (request, response) => {
    const pid = Number(request.body?.pid)
    const force = Boolean(request.body?.force)

    if (!Number.isInteger(pid) || pid <= 1) {
      response.status(400).json({ error: 'A valid PID greater than 1 is required.' })
      return
    }

    if (pid === process.pid) {
      response.status(400).json({ error: 'watsOn will not stop its own API process.' })
      return
    }

    try {
      const result = await stopProcess(pid, force)
      response.json(result)
    } catch (error) {
      response.status(500).json({
        error: error instanceof Error ? error.message : 'Unable to stop process',
      })
    }
  })

  if (!isDev && existsSync(distDir)) {
    app.use(express.static(distDir))
    app.use((request, response, next) => {
      if (request.path.startsWith('/api')) {
        next()
        return
      }
      response.sendFile(join(distDir, 'index.html'))
    })
  }

  return app
}

export function startServer({
  host = '127.0.0.1',
  isDev = process.argv.includes('--dev') || process.env.NODE_ENV === 'development',
  log = true,
  port = Number(process.env.PORT ?? 4141),
  rootDir = defaultRootDir,
  uiPort = Number(process.env.WATSON_UI_PORT ?? 5173),
} = {}) {
  let apiPort = Number(port)
  const app = createApp({
    getApiPort: () => apiPort,
    isDev,
    rootDir,
    uiPort,
  })

  return new Promise((resolve, reject) => {
    const server = app.listen(apiPort, host)

    server.once('error', reject)
    server.once('listening', () => {
      const address = server.address()
      apiPort = typeof address === 'object' && address ? address.port : apiPort
      const url = `http://${host}:${apiPort}`
      const uiHint = isDev ? `http://127.0.0.1:${uiPort}` : url

      if (log) {
        console.log(`watsOn API listening on ${url}`)
        console.log(`Open ${uiHint}`)
      }

      resolve({
        app,
        close: () => new Promise((done) => server.close(done)),
        host,
        port: apiPort,
        server,
        url,
      })
    })
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await startServer()
}

function loadLocalEnv(workspaceRoot) {
  for (const fileName of ['.env.local', '.env']) {
    const filePath = join(workspaceRoot, fileName)
    if (!existsSync(filePath)) continue

    const lines = readFileSync(filePath, 'utf8').split(/\r?\n/)
    for (const line of lines) {
      const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
      if (!match || process.env[match[1]]) continue
      const value = match[2].replace(/^['"]|['"]$/g, '')
      process.env[match[1]] = value
    }
  }
}
