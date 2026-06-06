# watsOn

**A tiny local dashboard for finding the dev servers, ports, and background services still running on your machine.**

watsOn helps you answer the question every developer eventually asks:

> What did I leave running?

It scans local listening TCP ports, explains what each process probably is, shows the evidence behind that guess, and helps you decide whether it is safe to stop.

Everything runs locally. There is no account, daemon, telemetry, or cloud service. The optional AI assistant uses your own OpenRouter API key and the key never reaches the browser.

## Highlights

- Finds listening TCP ports on macOS, Linux, and Windows.
- Identifies likely dev servers, databases, AI tools, tunnels, browser automation ports, and long-running local services.
- Shows process name, PID, parent process, command, host, port, source scanner, and project path when available.
- Explains every classification with concrete evidence, such as command text, known ports, parent process, or `lsof` details.
- Separates services into `Likely yours`, `Normal`, and `Unsure` so the main view stays useful.
- Provides cautious stop guidance: safe to stop, inspect first, or do not stop.
- Stops non-system processes with `SIGTERM` or `taskkill`, with force-stop available from the inspector.
- Detects stale `lsof` scans and other diagnostic commands left behind by tooling.
- Lets you keep a local ignore list for services you expect to leave running.
- Includes an optional OpenRouter assistant for asking questions about a selected listener.
- Packages as an unsigned personal macOS app with Electron.

## Why

Modern local development can leave a lot behind:

- Vite and Next.js servers from old agent runs.
- Databases started for a quick test.
- Storybook, Prisma Studio, tunnels, or browser automation sessions.
- Diagnostic commands that should have exited but did not.

watsOn is intentionally conservative. It treats a listening port as evidence, not a verdict. It will show why something looks relevant, but it avoids claiming a process is forgotten or safe to kill unless the evidence is strong.

## Install

```bash
git clone https://github.com/cobibean/watsOn.git
cd watsOn
npm install
```

## Run Locally

Start the local API and Vite UI:

```bash
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

For a production-style local run:

```bash
npm run build
npm start
```

Open:

```text
http://127.0.0.1:4141
```

## Optional AI Assistant

watsOn can ask any OpenRouter chat model about a selected listener.

1. Create an OpenRouter API key.
2. Copy the example env file:

   ```bash
   cp .env.example .env.local
   ```

3. Set your key:

   ```bash
   OPENROUTER_API_KEY=your_key_here
   OPENROUTER_MODEL=openrouter/auto
   ```

4. Restart `npm run dev`.

The browser never receives the key. The local server reads it from `.env.local` or `.env`, then sends selected service evidence to OpenRouter only when you ask the assistant a question.

## Personal macOS App

watsOn can be packaged as an unsigned personal Mac app. This does not require an Apple Developer ID.

```bash
npm run mac:pack
open release/mac-arm64/watsOn.app
```

For a quick local app launch without creating a release bundle:

```bash
npm run mac:open
```

The packaged app starts its own private localhost server on a random port and loads the built UI in an Electron window. It is intentionally unsigned for now.

If macOS blocks a downloaded copy later, right-click the app and choose **Open**, or remove quarantine for your local copy:

```bash
xattr -dr com.apple.quarantine release/mac-arm64/watsOn.app
```

## How It Works

watsOn combines native OS tools with process inspection:

| Platform | Scanner |
| --- | --- |
| macOS | `netstat`, timeout-protected `lsof`, and `ps` |
| Linux | `ss`, `netstat`, timeout-protected `lsof`, and `ps` |
| Windows | `netstat` and PowerShell process details |

Each listener is enriched with process details and classified into one of three buckets:

| Bucket | Meaning |
| --- | --- |
| `Likely yours` | Project commands, package runners, dev servers, databases, AI tools, tunnels, or ports strongly associated with developer workflows. |
| `Normal` | OS services, app helpers, browser helpers, updaters, VPN agents, and vendor background services. These are hidden from the main list by default. |
| `Unsure` | Local listeners with too little evidence to judge. |

## Privacy And Safety

- watsOn binds to localhost.
- There is no telemetry.
- There is no hosted backend.
- There is no account system.
- API keys belong in `.env.local` or `.env`, both of which are ignored by git.
- The optional OpenRouter assistant is only called when you ask it a question.
- Stop actions are blocked for protected/system processes and for watsOn's own API process.

## Development

```bash
npm install
npm run dev
```

Useful checks:

```bash
npm run lint
npm run build
```

The app is built with:

- React
- TypeScript
- Vite
- Express
- Electron
- Lucide React

## Contributing

Contributions are welcome.

Good first areas:

- Add better classification rules for common local tools.
- Improve Windows and Linux process evidence.
- Add tests around scanner parsing and stop safety.
- Polish the Electron packaging flow.
- Improve accessibility and keyboard navigation.

Please keep changes conservative around process stopping. The project should prefer useful caution over false confidence.

## License

MIT. See [LICENSE](LICENSE).
