# gireng — Frontend Technical Specification

## 1. Tech Stack

| Category | Technology | Version |
|----------|------------|---------|
| Framework | React + TypeScript | 19.2 / 5.9 |
| Build Tool | Vite | 7.2 |
| Styling | Tailwind CSS | 3.4 |
| UI Primitives | Radix UI (20+ primitives) | latest |
| UI Components | shadcn/ui | latest |
| Animation | Framer Motion | 12.29 |
| Icons | Lucide React | 0.562 |
| Charts | Recharts | 2.15 |
| Markdown | react-markdown + remark-gfm | 10.1 / 4.0 |
| Code Highlighting | PrismJS | 1.30 |
| Forms | React Hook Form + Zod | 7.70 / 4.3 |
| Resizable Panels | react-resizable-panels | 4.2 |
| Toasts | Sonner | 2.0 |
| Theme | next-themes | 0.4 |
| Command Palette | cmdk | 1.1 |
| Drawer | Vaul | 1.1 |
| Carousel | embla-carousel-react | 8.6 |
| Date Utilities | date-fns | 4.1 |

## 2. Tailwind Configuration

```javascript
// tailwind.config.js extensions
{
  theme: {
    extend: {
      colors: {
        // Backgrounds
        'bg-primary': '#0D1117',
        'bg-secondary': '#161B22',
        'bg-tertiary': '#1C2128',
        'bg-hover': '#21262D',

        // Accents
        'accent-blue': '#58A6FF',
        'accent-purple': '#A371F7',
        'accent-green': '#3FB950',
        'accent-red': '#F85149',
        'accent-orange': '#D29922',
        'accent-yellow': '#F0883E',

        // Text
        'text-primary': '#F0F6FC',
        'text-secondary': '#8B949E',
        'text-muted': '#6E7681',

        // Border
        'border-default': '#30363D',
        'border-subtle': '#21262D',
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['"SF Mono"', 'Monaco', '"Cascadia Code"', 'monospace'],
      },
    },
  },
}
```

## 3. Component Inventory

### Layout Components (5)

| Component | File | Description |
|-----------|------|-------------|
| `MainLayout` | `layout/MainLayout.tsx` | App shell — sidebar + main + right panel |
| `Sidebar` | `layout/Sidebar.tsx` | Collapsible left navigation |
| `TabbedPanel` | `layout/TabbedPanel.tsx` | Right panel (Resources/Code/Report tabs) with export dropdown |
| `ResourcesPanel` | `layout/ResourcesPanel.tsx` | Resource list in right panel |
| `ResizablePanel` | `layout/ResizablePanel.tsx` | Draggable panel resize |

### Chat Components (11)

| Component | File | Description |
|-----------|------|-------------|
| `ChatInterface` | `chat/ChatInterface.tsx` | Main chat container |
| `WelcomeScreen` | `chat/WelcomeScreen.tsx` | Initial welcome view |
| `MessageBubble` | `chat/MessageBubble.tsx` | Individual message display |
| `ChatInput` | `chat/ChatInput.tsx` | Message input area |
| `QuickActionChips` | `chat/QuickActionChips.tsx` | Quick action buttons |
| `ModelSelector` | `chat/ModelSelector.tsx` | AI model dropdown |
| `ToolCallCard` | `chat/ToolCallCard.tsx` | Tool execution display |
| `CodeBlock` | `chat/CodeBlock.tsx` | Syntax-highlighted code in chat |
| `AnalysisCompletedCard` | `chat/AnalysisCompletedCard.tsx` | Post-analysis card with export buttons (HTML + PDF) |
| `AgentPicker` | `chat/AgentPicker.tsx` | Agent selection |
| `AgentSelector` | `chat/AgentSelector.tsx` | Agent selector dropdown |

### Analysis Components (9)

| Component | File | Description |
|-----------|------|-------------|
| `AnalysisHeader` | `analysis/AnalysisHeader.tsx` | Results header with threat score |
| `AnalysisTabs` | `analysis/AnalysisTabs.tsx` | Tab navigation |
| `AnalysisSection` | `analysis/AnalysisSection.tsx` | Content section wrapper |
| `AnalyzerList` | `analysis/AnalyzerList.tsx` | Analyzer details list |
| `AnalyzerItem` | `analysis/AnalyzerItem.tsx` | Expandable analyzer card |
| `CircularProgress` | `analysis/CircularProgress.tsx` | SVG progress ring |
| `StatusBadge` | `analysis/StatusBadge.tsx` | Color-coded status badge |
| `TagCloud` | `analysis/TagCloud.tsx` | Category tags display |
| `CallGraphView` | `analysis/CallGraphView.tsx` | Call graph visualisation |

### Other Components

| Component | File | Description |
|-----------|------|-------------|
| `CodeViewer` | `code/CodeViewer.tsx` | Syntax-highlighted code display |
| `MarkdownContent` | `common/MarkdownContent.tsx` | Markdown renderer |
| `DataTable` | `data/DataTable.tsx` | Generic data table |
| `ShareModal` | `modals/ShareModal.tsx` | Share/export modal |

### shadcn/ui Components (~50)

Pre-installed Radix-based components in `components/ui/`: accordion, alert, alert-dialog, avatar, badge, breadcrumb, button, button-group, calendar, card, carousel, chart, checkbox, collapsible, command, context-menu, dialog, drawer, dropdown-menu, empty, field, form, hover-card, input, input-group, input-otp, item, kbd, label, menubar, navigation-menu, pagination, popover, progress, radio-group, resizable, scroll-area, select, separator, sheet, sidebar, skeleton, slider, sonner, spinner, switch, table, tabs, textarea, toggle, toggle-group, tooltip.

## 4. Project File Structure

```
app/
├── index.html
├── package.json
├── vite.config.ts
├── tsconfig.json
├── tsconfig.app.json
├── tsconfig.node.json
├── tailwind.config.js
├── postcss.config.js
├── eslint.config.js
├── components.json            # shadcn/ui config
├── Dockerfile.ui
│
└── src/
    ├── App.tsx                # App root — chat + panels + state
    ├── App.css
    ├── main.tsx               # Entry point
    ├── index.css              # Global styles + Tailwind
    │
    ├── agents/
    │   ├── ghidra-agent.ts    # Ghidra agent config
    │   └── radare-agent.ts    # Radare2 agent config
    │
    ├── components/
    │   ├── analysis/          # 9 analysis components
    │   ├── chat/              # 11 chat components
    │   ├── code/              # Code viewer
    │   ├── common/            # Shared components
    │   ├── data/              # Data table
    │   ├── layout/            # 5 layout components
    │   ├── modals/            # Modals
    │   ├── report/            # Report components
    │   └── ui/                # ~50 shadcn/ui primitives
    │
    ├── data/
    │   └── mockData.ts        # Mock data for development
    │
    ├── hooks/
    │   └── use-mobile.ts      # Mobile detection hook
    │
    ├── lib/
    │   ├── api.ts             # REST API client + export URL builders
    │   └── utils.ts           # Utility functions (cn, etc.)
    │
    └── types/
        └── index.ts           # TypeScript type definitions
```

## 5. API Integration (`lib/api.ts`)

The API client provides:

| Function | Description |
|----------|-------------|
| `getApiBaseUrl()` | Resolves API URL from env or defaults to `http://localhost:8080` |
| `getWsUrl()` | Resolves WebSocket URL |
| `uploadBinary(file)` | Upload binary for analysis |
| `getStatus(sessionId)` | Poll analysis status |
| `sendQuery(sessionId, query)` | Send follow-up query |
| `getAnalyzers(hash)` | Fetch Ghidra + R2 results |
| `getFileTree(hash)` | Fetch decompiled file tree |
| `getFileContent(hash, fileId)` | Fetch decompiled function code |
| `getReports(hash)` | Fetch reports list |
| `getExportHtmlUrl(hash)` | Build HTML export URL |
| `getExportTextUrl(hash)` | Build text export URL |
| `getExportPdfUrl(hash)` | Build PDF export URL |

## 6. Type Definitions (`types/index.ts`)

```typescript
export interface Message {
  id: string;
  content: string;
  isUser: boolean;
  timestamp: Date;
  toolCalls?: ToolCall[];
}

export interface ToolCall {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  result?: any;
}

export interface AnalysisResult {
  hash: string;
  size: string;
  type: string;
  status: string;
  duration: string;
  started: string;
  completed: string;
  verdict: string;
  threatScore: number;
  maxScore: number;
  tags: string[];
}

export interface Analyzer {
  id: string;
  name: string;
  source: string;
  verdict: 'Clean' | 'Malware' | 'Suspicious' | 'Not_extracted';
  details?: AnalyzerDetails;
}

export interface Model {
  id: string;
  name: string;
  icon: string;
  type: 'gemini' | 'gpt' | 'other';
}

export interface QuickAction {
  id: string;
  label: string;
  icon: string;
}

export interface Chat {
  id: string;
  title: string;
  timestamp: Date;
}

export interface FileNode {
  id: string;
  name: string;
  type: 'file' | 'folder';
  children?: FileNode[];
}
```

## 7. Animation Strategy

| Interaction | Implementation |
|-------------|----------------|
| Page load | Framer Motion `staggerChildren: 0.05`, `y: 10 → 0` + opacity |
| Sidebar toggle | `AnimatePresence` with width animation `260px ↔ 60px` |
| Chat message appear | `initial={{ opacity: 0, y: 10 }}` with stagger |
| Tool card expand | `AnimatePresence` with height `auto` |
| Progress ring | SVG `stroke-dasharray` + `stroke-dashoffset` |
| Tab underline | `layoutId="tab-underline"` shared element |
| Analyzer expand | `AnimatePresence` + chevron rotation |
| Hover states | Tailwind `transition-all duration-150 hover:bg-bg-hover` |

### Timing

- **Fast (micro)**: 150ms — hover, focus, active states
- **Normal (UI)**: 200ms — card hovers, button transitions
- **Medium**: 300ms — dropdowns, tooltips
- **Slow (page)**: 400ms — staggered reveals

## 8. Build & Development

```bash
# Install
npm ci

# Development (hot reload at :5173)
npm run dev

# Production build
npm run build

# Lint
npm run lint

# Preview production build
npm run preview
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `http://${HOST}:${API_PORT}` | Backend API URL |
| `VITE_WS_URL` | `ws://${HOST}:${API_PORT}/stream` | WebSocket URL |
