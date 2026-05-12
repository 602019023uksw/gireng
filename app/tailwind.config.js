import tailwindcssAnimate from "tailwindcss-animate";

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive) / <alpha-value>)",
          foreground: "hsl(var(--destructive-foreground) / <alpha-value>)",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        sidebar: {
          DEFAULT: "hsl(var(--sidebar-background))",
          foreground: "hsl(var(--sidebar-foreground))",
          primary: "hsl(var(--sidebar-primary))",
          "primary-foreground": "hsl(var(--sidebar-primary-foreground))",
          accent: "hsl(var(--sidebar-accent))",
          "accent-foreground": "hsl(var(--sidebar-accent-foreground))",
          border: "hsl(var(--sidebar-border))",
          ring: "hsl(var(--sidebar-ring))",
        },
        // Material-inspired application colors
        'bg-primary': '#f8fafd',
        'bg-secondary': '#ffffff',
        'bg-tertiary': '#f1f4f9',
        'bg-hover': '#edf3fd',
        'bg-glass': 'rgba(255, 255, 255, 0.82)',
        'bg-glass-strong': 'rgba(255, 255, 255, 0.94)',
        'accent-blue': '#1a73e8',
        'accent-purple': '#6750a4',
        'accent-cyan': '#0b57d0',
        'accent-green': '#188038',
        'accent-red': '#d93025',
        'accent-orange': '#e8710a',
        'accent-yellow': '#fbbc04',
        'text-primary': '#202124',
        'text-secondary': '#5f6368',
        'text-muted': '#80868b',
        'border-default': '#dadce0',
        'border-subtle': '#edf0f4',
        'border-glow': 'rgba(26, 115, 232, 0.24)',
        'terminal-red': '#ea4335',
        'terminal-yellow': '#fbbc04',
        'terminal-green': '#34a853',
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Monaco', 'monospace'],
      },
      borderRadius: {
        xl: "calc(var(--radius) + 4px)",
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
        xs: "calc(var(--radius) - 6px)",
      },
      boxShadow: {
        xs: "0 1px 2px 0 rgb(60 64 67 / 0.12)",
        'glass': '0 1px 3px rgba(60, 64, 67, 0.18), 0 1px 2px rgba(60, 64, 67, 0.12)',
        'glass-strong': '0 8px 24px rgba(60, 64, 67, 0.12), 0 2px 6px rgba(60, 64, 67, 0.08)',
        'glow-purple': '0 0 0 4px rgba(103, 80, 164, 0.12)',
        'glow-cyan': '0 0 0 4px rgba(26, 115, 232, 0.12)',
        'glow-green': '0 0 0 4px rgba(24, 128, 56, 0.12)',
        'glow-red': '0 0 0 4px rgba(217, 48, 37, 0.12)',
      },
      backdropBlur: {
        xs: '2px',
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        "caret-blink": {
          "0%,70%,100%": { opacity: "1" },
          "20%,50%": { opacity: "0" },
        },
        "fade-in": {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        "slide-up": {
          from: { opacity: "0", transform: "translateY(10px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-glow": {
          "0%, 100%": { boxShadow: "0 0 20px rgba(168, 85, 247, 0.25)" },
          "50%": { boxShadow: "0 0 30px rgba(168, 85, 247, 0.4)" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "caret-blink": "caret-blink 1.25s ease-out infinite",
        "fade-in": "fade-in 0.3s ease-out forwards",
        "slide-up": "slide-up 0.4s ease-out forwards",
        "pulse-glow": "pulse-glow 2s ease-in-out infinite",
      },
    },
  },
  plugins: [tailwindcssAnimate],
}
