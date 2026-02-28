# gireng — Frontend

React frontend for the gireng AI-powered binary analysis platform.

## Features

- **Dark Theme UI** — GitHub-inspired dark palette with accent colours
- **Chat Interface** — AI-powered chat with code blocks, tool call cards, and analysis completion cards
- **Analysis Dashboard** — File analysis results with threat scoring, MITRE ATT&CK tags, and circular progress
- **Dual-Analyzer View** — Side-by-side Ghidra + Radare2 results
- **Code Viewer** — Syntax-highlighted decompiled code with tabs
- **Resizable Panels** — Adjustable sidebar and right panel widths
- **Export** — Download reports as HTML, PDF, or text directly from the UI
- **Call Graph View** — Visual attack chain display
- **Real-Time Streaming** — WebSocket-based live analysis progress

## Tech Stack

| Category | Package | Version |
|----------|---------|---------|
| Framework | React + TypeScript | 19.2 / 5.9 |
| Build | Vite | 7.2 |
| Styling | Tailwind CSS | 3.4 |
| UI Primitives | Radix UI (20+ primitives) | latest |
| Components | shadcn/ui (~50 components) | latest |
| Animation | Framer Motion | 12.29 |
| Icons | Lucide React | 0.562 |
| Charts | Recharts | 2.15 |
| Markdown | react-markdown + remark-gfm | 10.1 |
| Code | PrismJS | 1.30 |
| Forms | React Hook Form + Zod | 7.70 / 4.3 |
| Panels | react-resizable-panels | 4.2 |
| Toasts | Sonner | 2.0 |

## Quick Start

```bash
# Install dependencies
npm ci

# Start development server (hot reload at :5173)
npm run dev

# Build for production
npm run build

# Lint
npm run lint
```

## Project Structure

```
src/
├── App.tsx                    # App root — chat + panels + state
├── main.tsx                   # Entry point
├── index.css                  # Global styles + Tailwind
│
├── agents/                    # Agent configs
│   ├── ghidra-agent.ts
│   └── radare-agent.ts
│
├── components/
│   ├── analysis/              # 9 analysis components (header, tabs, sections, progress)
│   ├── chat/                  # 11 chat components (interface, messages, input, completion card)
│   ├── code/                  # Code viewer
│   ├── common/                # Shared components (markdown renderer)
│   ├── data/                  # Data table
│   ├── layout/                # 5 layout components (sidebar, panels, tabs)
│   ├── modals/                # Share modal
│   ├── report/                # Report components
│   └── ui/                    # ~50 shadcn/ui primitives
│
├── data/
│   └── mockData.ts            # Mock data for development
│
├── hooks/
│   └── use-mobile.ts          # Mobile detection
│
├── lib/
│   ├── api.ts                 # REST API client + export URL builders
│   └── utils.ts               # Utility functions
│
└── types/
    └── index.ts               # TypeScript type definitions
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `http://localhost:8080` | Backend API URL |
| `VITE_WS_URL` | `ws://localhost:8080/stream` | WebSocket URL |

## Docker

The UI runs as a Docker service via `Dockerfile.ui`:

```bash
# Built and started via docker compose
docker compose up -d ui
```

The Vite preview server runs on port **4173** inside the container.

## Integration

The frontend communicates with the FastAPI backend (38 endpoints) via REST and WebSocket. See [BACKEND_INTEGRATION_GUIDE.md](BACKEND_INTEGRATION_GUIDE.md) for data structures and endpoint details.

Key API interactions:
- `POST /analyze/upload` — Upload binary
- `WS /stream/{session_id}` — Real-time analysis events
- `GET /api/analysis/{hash}/analyzers` — Ghidra + R2 results
- `GET /api/analysis/{hash}/export/pdf` — PDF report download
- `GET /api/analysis/{hash}/export/html` — HTML report download
