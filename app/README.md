# IrengSec - Cybersecurity Analysis Platform Template

A modern, glass-morphism styled React template for building AI-powered malware analysis and reverse engineering platforms.

![Glass Terminal Theme](https://irengsec.ai)

## Features

- **Glass Morphism UI** - Modern translucent design with backdrop blur effects
- **Terminal Aesthetic** - macOS-style window controls (red, yellow, green dots)
- **Dark Theme** - Purple/cyan accent colors on dark background
- **Chat Interface** - AI-powered chat with code blocks and tool calls
- **Analysis Dashboard** - File analysis results with threat scoring
- **Code Viewer** - Syntax-highlighted code display with tabs
- **Resizable Panels** - Adjustable sidebar and right panel widths
- **Model Selector** - Switch between AI models (Gemini, Claude, GPT)

## Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **Framer Motion** - Animations
- **shadcn/ui** - UI components
- **Lucide React** - Icons

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Project Structure

```
src/
├── components/
│   ├── analysis/          # Analysis view components
│   ├── chat/              # Chat interface components
│   ├── code/              # Code viewer components
│   ├── data/              # Data display components
│   ├── layout/            # Layout components
│   ├── modals/            # Modal components
│   └── report/            # Report viewer components
├── data/
│   └── mockData.ts        # Template data (replace with API)
├── types/
│   └── index.ts           # TypeScript type definitions
├── App.tsx               # Main application
└── index.css             # Global styles
```

## Backend Integration

See [BACKEND_INTEGRATION_GUIDE.md](./BACKEND_INTEGRATION_GUIDE.md) for detailed API documentation.

### Key API Endpoints

```
GET    /api/models              # Available AI models
GET    /api/chats               # Chat history
POST   /api/chats/:id/messages  # Send message
GET    /api/analysis/:hash      # Analysis results
GET    /api/analysis/:hash/analyzers  # Analyzer results (Ghidra, Radare)
```

### WebSocket Events

```javascript
// Analysis progress
{ type: 'analysis:progress', hash: '...', progress: 50 }

// Analysis completed
{ type: 'analysis:completed', hash: '...', result: {...} }

// New message
{ type: 'message', chatId: '...', message: {...} }
```

## Customization

### Colors

Edit `tailwind.config.js`:

```javascript
colors: {
  'accent-purple': '#a855f7',
  'accent-cyan': '#22d3ee',
  'terminal-red': '#ff5f56',
  'terminal-yellow': '#ffbd2e',
  'terminal-green': '#27c93f',
}
```

### Analyzers

The template is configured for **Ghidra** and **Radare** only. Edit `src/data/mockData.ts`:

```typescript
export const mockAnalyzers: Analyzer[] = [
  {
    id: 'ghidra',
    name: 'Ghidra Reverse Engineer Agent',
    // ...
  },
  {
    id: 'radare',
    name: 'Radare Reverse Engineer Agent',
    // ...
  },
];
```

## Environment Variables

```bash
# .env
VITE_API_BASE_URL=https://api.yourdomain.com
VITE_WS_URL=wss://api.yourdomain.com/ws
```

## License

MIT License - Feel free to use for commercial projects.

## Support

For backend integration questions, refer to the [Integration Guide](./BACKEND_INTEGRATION_GUIDE.md).
