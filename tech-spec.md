# gireng - Technical Specification

## 1. Tech Stack Overview

| Category | Technology |
|----------|------------|
| Framework | React 18 + TypeScript |
| Build Tool | Vite |
| Styling | Tailwind CSS 3.4 |
| UI Components | shadcn/ui |
| Animation | Framer Motion |
| Icons | Lucide React |
| State Management | React Context + useState |

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
      animation: {
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
        'progress': 'progress 2s ease-out forwards',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        progress: {
          '0%': { strokeDashoffset: '100' },
          '100%': { strokeDashoffset: '0' },
        },
      },
    },
  },
}
```

## 3. Component Inventory

### Shadcn/UI Components (Pre-installed)
- Button (customize: ghost variant, sizes)
- Input (customize: dark theme)
- Card (customize: dark borders)
- Badge (customize: pill style)
- Tabs (customize: underline style)
- Accordion (for expandable sections)
- Tooltip
- Dropdown Menu
- Scroll Area

### Custom Components

#### Layout Components
| Component | Props | Description |
|-----------|-------|-------------|
| `Sidebar` | `collapsed: boolean` | Main navigation sidebar |
| `SidebarNav` | `items: NavItem[]` | Navigation icon list |
| `ChatList` | `chats: Chat[]` | Chat history list |
| `MainLayout` | `children: ReactNode` | App shell layout |
| `ResourcesPanel` | `files: File[], analyses: Analysis[]` | Right resource sidebar |

#### Chat Components
| Component | Props | Description |
|-----------|-------|-------------|
| `ChatInterface` | `messages: Message[]` | Main chat container |
| `WelcomeScreen` | `userName: string` | Initial welcome view |
| `MessageBubble` | `message: Message, isUser: boolean` | Individual message |
| `ChatInput` | `onSend: (text: string) => void` | Message input area |
| `QuickActionChips` | `actions: QuickAction[]` | Quick action buttons |
| `ModelSelector` | `models: Model[], selected: string` | AI model dropdown |
| `ToolCallCard` | `tool: ToolCall, status: string` | Tool execution display |

#### Analysis Components
| Component | Props | Description |
|-----------|-------|-------------|
| `AnalysisHeader` | `analysis: AnalysisResult` | Results header card |
| `CircularProgress` | `value: number, max: number, color: string` | SVG progress ring |
| `StatusBadge` | `status: string` | Color-coded status |
| `TagCloud` | `tags: string[]` | Category tags display |
| `AnalysisTabs` | `activeTab: string` | Tab navigation |
| `AnalyzerList` | `analyzers: Analyzer[]` | Analyzer details list |
| `AnalyzerItem` | `analyzer: Analyzer, expanded: boolean` | Expandable analyzer |
| `AnalysisSection` | `title: string, children: ReactNode` | Content section |
| `ExecutionLogs` | `logs: string[]` | Log display footer |

#### Resource Components
| Component | Props | Description |
|-----------|-------|-------------|
| `ResourceSection` | `title: string, count: number` | Collapsible section |
| `FileTree` | `files: FileNode[]` | Hierarchical file list |
| `AnalysisCard` | `analysis: Analysis` | Analysis summary card |

## 4. Animation Implementation Plan

| Interaction Name | Tech Choice | Implementation Logic |
|------------------|-------------|---------------------|
| Page Load | Framer Motion | `staggerChildren: 0.05` on container, `y: 10 -> 0` + opacity fade on items |
| Sidebar Toggle | Framer Motion | `AnimatePresence` with width animation `260px <-> 60px` |
| Chat Message Appear | Framer Motion | `initial={{ opacity: 0, y: 10 }}` `animate={{ opacity: 1, y: 0 }}` with stagger |
| Tool Card Expand | Framer Motion | `AnimatePresence` with height `auto` animation |
| Progress Ring | CSS + SVG | `stroke-dasharray` + `stroke-dashoffset` animation on mount |
| Tab Underline | Framer Motion | `layoutId="tab-underline"` for shared element transition |
| Analyzer Expand | Framer Motion | `AnimatePresence` with `height: auto`, chevron rotates 90deg |
| Hover States | Tailwind | `transition-all duration-150 hover:bg-bg-hover` |
| Button Press | Tailwind | `active:scale-[0.98]` |
| Dropdown Open | Framer Motion | `initial={{ opacity: 0, y: -10 }}` `animate={{ opacity: 1, y: 0 }}` |
| Card Hover | Tailwind | `hover:border-border-default/80 transition-colors duration-200` |
| Tag Scroll | CSS | `overflow-x-auto` with custom scrollbar styling |
| Resource Section Toggle | Framer Motion | `AnimatePresence` with height animation |

### Animation Timing Reference
- Fast (micro): 150ms - hover, focus, active states
- Normal (UI): 200ms - card hovers, button transitions
- Medium (content): 300ms - dropdowns, tooltips, modals
- Slow (page): 400ms - page transitions, staggered reveals

### Easing Functions
- Default: `[0.4, 0, 0.2, 1]` (ease-out)
- Enter: `[0, 0, 0.2, 1]` (decelerate)
- Exit: `[0.4, 0, 1, 1]` (accelerate)
- Spring: `{ type: "spring", stiffness: 300, damping: 30 }`

## 5. Project File Structure

```
/mnt/okcomputer/output/app/
├── src/
│   ├── components/
│   │   ├── ui/                    # shadcn/ui components
│   │   ├── layout/
│   │   │   ├── Sidebar.tsx
│   │   │   ├── MainLayout.tsx
│   │   │   └── ResourcesPanel.tsx
│   │   ├── chat/
│   │   │   ├── ChatInterface.tsx
│   │   │   ├── WelcomeScreen.tsx
│   │   │   ├── MessageBubble.tsx
│   │   │   ├── ChatInput.tsx
│   │   │   ├── QuickActionChips.tsx
│   │   │   ├── ModelSelector.tsx
│   │   │   └── ToolCallCard.tsx
│   │   └── analysis/
│   │       ├── AnalysisHeader.tsx
│   │       ├── CircularProgress.tsx
│   │       ├── StatusBadge.tsx
│   │       ├── TagCloud.tsx
│   │       ├── AnalysisTabs.tsx
│   │       ├── AnalyzerList.tsx
│   │       ├── AnalyzerItem.tsx
│   │       ├── AnalysisSection.tsx
│   │       └── ExecutionLogs.tsx
│   ├── hooks/
│   │   └── useAnimation.ts
│   ├── types/
│   │   └── index.ts
│   ├── data/
│   │   └── mockData.ts
│   ├── lib/
│   │   └── utils.ts
│   ├── App.tsx
│   ├── main.tsx
│   └── index.css
├── public/
├── index.html
├── tailwind.config.js
├── vite.config.ts
└── package.json
```

## 6. Package Installation List

```bash
# Animation library
npm install framer-motion

# Icons
npm install lucide-react

# Utility
npm install clsx tailwind-merge
```

## 7. Type Definitions

```typescript
// types/index.ts

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

export interface AnalyzerDetails {
  executiveSummary: string;
  staticAnalysis: string;
  behavioralAnalysis: string;
  iocs: string;
  conclusion: string;
  executionLogs: string[];
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

## 8. Key Implementation Notes

### Circular Progress Component
- Use SVG with two `<circle>` elements
- Background circle: gray stroke
- Progress circle: colored stroke with `stroke-dasharray` and `stroke-dashoffset`
- Calculate offset: `circumference - (value / max) * circumference`
- Animate with CSS transition or Framer Motion

### Tab Underline Animation
- Use Framer Motion's `layoutId` for shared element
- Underline follows active tab automatically
- Smooth spring animation between positions

### Sidebar Collapse
- Use Framer Motion's `animate` prop for width
- Content visibility toggles with `opacity` and `display`
- Icons remain visible, text fades out

### Message Stagger Animation
- Container uses `staggerChildren: 0.1`
- Each message animates `y: 10 -> 0` with opacity
- New messages trigger animation on mount

### Analyzer Expand/Collapse
- Use `AnimatePresence` for enter/exit
- Content wrapper animates `height: 0 -> auto`
- Chevron icon rotates with `animate={{ rotate: expanded ? 90 : 0 }}`
