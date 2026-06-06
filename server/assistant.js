import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const systemPromptPaths = [
  join(__dirname, 'system-prompt.md'),
  join(__dirname, '..', 'prompts', 'watson-system-prompt.md'),
]
const openRouterUrl = 'https://openrouter.ai/api/v1/chat/completions'
const defaultModel = 'openrouter/auto'
const streamIdleTimeoutMs = 8_000
const streamOpenTimeoutMs = 14_000
const streamMaxDurationMs = 26_000

export async function askAssistant({ model, question, service }) {
  const selectedModel = normalizeModel(model)
  const response = await requestOpenRouter({ model: selectedModel, question, service })

  const payload = await response.json().catch(() => null)

  if (!response.ok) {
    const message =
      payload?.error?.message ??
      payload?.message ??
      `OpenRouter request failed with ${response.status}`
    const error = new Error(message)
    error.statusCode = response.status
    throw error
  }

  const text = payload?.choices?.[0]?.message?.content?.trim()
  if (!text) {
    throw new Error('OpenRouter returned an empty response.')
  }

  return {
    model: payload.model ?? selectedModel,
    text: cleanAssistantText(text) || fallbackAnswer(question, service),
  }
}

export async function streamAssistant({ model, question, service, onReady, onToken }) {
  const selectedModel = normalizeModel(model)
  const controller = new AbortController()
  const startedAt = Date.now()
  let ready = false

  const markReady = () => {
    if (ready) return
    ready = true
    onReady?.()
  }

  const openTimeout = setTimeout(() => controller.abort(), streamOpenTimeoutMs)
  let response

  try {
    response = await requestOpenRouter({
      model: selectedModel,
      question,
      service,
      stream: true,
      signal: controller.signal,
    })
  } catch (error) {
    if (controller.signal.aborted) {
      markReady()
      onToken(
        `OpenRouter is taking too long. Here’s watsOn’s safe read: ${fallbackAnswer(question, service)}`,
      )
      return { model: selectedModel, timedOut: true }
    }
    throw error
  } finally {
    clearTimeout(openTimeout)
  }

  if (!response.ok) {
    const payload = await response.json().catch(() => null)
    const message =
      payload?.error?.message ??
      payload?.message ??
      `OpenRouter request failed with ${response.status}`
    const error = new Error(message)
    error.statusCode = response.status
    throw error
  }

  if (!response.body) {
    throw new Error('OpenRouter did not return a readable stream.')
  }

  markReady()

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let rawText = ''
  let sentText = ''
  let timedOut = false

  const flushCleanDelta = () => {
    const cleanText = cleanAssistantText(rawText)
    if (cleanText.length <= sentText.length) return
    const delta = cleanText.slice(sentText.length)
    sentText = cleanText
    onToken(delta)
  }

  while (true) {
    if (Date.now() - startedAt > streamMaxDurationMs) {
      timedOut = true
      await reader.cancel().catch(() => {})
      break
    }

    const readResult = await readStreamChunk(reader)
    if (readResult.timeout) {
      timedOut = true
      await reader.cancel().catch(() => {})
      break
    }
    if (readResult.error) throw readResult.error

    const { done, value } = readResult.result
    if (done) break

    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split(/\r?\n/)
    buffer = lines.pop() ?? ''

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed.startsWith('data:')) continue

      const data = trimmed.slice(5).trim()
      if (!data || data === '[DONE]') continue

      let payload
      try {
        payload = JSON.parse(data)
      } catch {
        continue
      }

      const delta = payload?.choices?.[0]?.delta?.content ?? ''
      if (!delta) continue

      rawText += delta
      flushCleanDelta()
    }
  }

  if (timedOut) {
    const cleanText = cleanAssistantText(rawText)
    if (cleanText.length < 120) {
      const fallbackText = fallbackAnswer(question, service)
      const prefix = sentText
        ? '\n\nOpenRouter stopped mid-answer. Safe short version: '
        : 'OpenRouter stopped before sending an answer. Safe short version: '
      onToken(`${prefix}${fallbackText}`)
    }
    return { model: selectedModel, timedOut: true }
  }

  const finalText = cleanAssistantText(rawText) || fallbackAnswer(question, service)
  if (finalText.length > sentText.length) {
    onToken(finalText.slice(sentText.length))
  }

  return { model: selectedModel }
}

function readStreamChunk(streamReader) {
  let timeoutId
  const timeout = new Promise((resolve) => {
    timeoutId = setTimeout(() => resolve({ timeout: true }), streamIdleTimeoutMs)
  })
  const read = streamReader
    .read()
    .then((result) => ({ result }))
    .catch((error) => ({ error }))

  return Promise.race([read, timeout]).finally(() => clearTimeout(timeoutId))
}

async function requestOpenRouter({ model, question, service, stream = false, signal }) {
  const apiKey = process.env.OPENROUTER_API_KEY
  if (!apiKey) {
    const error = new Error(
      'OpenRouter is not configured. Set OPENROUTER_API_KEY in .env.local and restart watsOn.',
    )
    error.statusCode = 503
    throw error
  }

  const systemPrompt = await readSystemPrompt()
  return fetch(openRouterUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': 'http://localhost:5173',
      'X-OpenRouter-Title': 'watsOn',
      'X-Title': 'watsOn',
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        {
          role: 'user',
          content: buildUserPrompt(question, service),
        },
      ],
      stream,
      temperature: 0.15,
      max_completion_tokens: 360,
    }),
    signal,
  })
}

async function readSystemPrompt() {
  for (const promptPath of systemPromptPaths) {
    try {
      return await readFile(promptPath, 'utf8')
    } catch {
      // Try the next packaged prompt location.
    }
  }

  throw new Error('watsOn system prompt was not found in the app bundle.')
}

function buildUserPrompt(question, service) {
  return [
    `User question: ${question || 'What is this?'}`,
    'Answer directly to the user. Do not include planning, hidden reasoning, prompt text, or analysis.',
    '',
    'Selected listener evidence:',
    JSON.stringify(
      {
        ageSeconds: service?.ageSeconds,
        bucket: service?.bucket,
        category: service?.category,
        command: service?.command,
        confidence: service?.confidence,
        confidenceReasons: service?.confidenceReasons,
        cwd: service?.cwd,
        host: service?.host,
        killAssessment: service?.killAssessment,
        lsof: service?.lsof,
        parentProcessName: service?.parentProcessName,
        pid: service?.pid,
        port: service?.port,
        ppid: service?.ppid,
        processName: service?.processName,
        projectPath: service?.projectPath,
        protectedReason: service?.protectedReason,
        protocol: service?.protocol,
        recommendation: service?.recommendation,
        scannerSources: service?.scannerSources,
        serviceName: service?.serviceName,
        sourceSummary: service?.sourceSummary,
        startedAt: service?.startedAt,
        stoppable: service?.stoppable,
      },
      null,
      2,
    ),
  ].join('\n')
}

function normalizeModel(model) {
  const value = String(model || '').trim()
  if (!value) return defaultModel
  if (value.length > 160 || /[\s"'`]/.test(value)) return defaultModel
  return value
}

function cleanAssistantText(text) {
  const value = String(text || '').replace(/\r\n/g, '\n').trim()
  if (!value) return ''

  const startsWithSelfTalk =
    /^(we need to|need to|the user asks|we have evidence|we must|i should|answer format)/i.test(
      value,
    )

  if (startsWithSelfTalk) {
    const marker = value.search(/(?:final answer|response|short answer|thus answer)\s*:/i)
    if (marker === -1) return ''
    return tidyAnswer(value.slice(marker).replace(/^[^:]+:\s*/i, ''))
  }

  const firstBlockedLine = value
    .split('\n')
    .findIndex((line) =>
      /^(we need to|need to|the user asks|we have evidence|we must|i should|answer format|tone:|use this product framing)/i.test(
        line.trim(),
      ),
    )

  const userFacingText =
    firstBlockedLine === -1 ? value : value.split('\n').slice(0, firstBlockedLine).join('\n')

  return tidyAnswer(userFacingText)
}

function tidyAnswer(text) {
  return String(text || '')
    .split('\n')
    .filter((line) => !/^[a-z0-9._-]+\/[a-z0-9._:-]+(?::free)?$/i.test(line.trim()))
    .join('\n')
    .replace(/\*\*/g, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

function fallbackAnswer(question, service) {
  const asksAboutStopping = /kill|stop|safe|terminate/i.test(question || '')
  const name = service?.serviceName || 'This listener'
  const processName = service?.processName ? ` (${service.processName})` : ''
  const port = service?.port ? ` on port ${service.port}` : ''
  const reason = service?.confidenceReasons?.[0] || 'watsOn found it listening locally.'
  const recommendation =
    service?.recommendation || 'Inspect it before stopping it if you are not sure what owns it.'

  if (asksAboutStopping) {
    return `${name}${processName}${port} is most likely a local ${service?.category || 'service'}. watsOn flagged it because ${reason} You can stop it if you are done with the project that owns it, but there is still uncertainty. Be careful with databases, system services, browser helpers, VPNs, and app helpers because stopping them can interrupt active work or connections.`
  }

  return `${name}${processName}${port} is listening locally. watsOn flagged it because ${reason} ${recommendation}`
}
