/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    container: {
      center: true,
      padding: '2rem',
      screens: {
        '2xl': '1400px',
      },
    },
    extend: {
      fontFamily: {
        sans: ['Inter', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      colors: {
        bg: {
          primary: 'var(--color-bg-primary)',
          secondary: 'var(--color-bg-secondary)',
          tertiary: 'var(--color-bg-tertiary)',
        },
        surface: {
          1: 'var(--color-surface-1)',
          2: 'var(--color-surface-2)',
          3: 'var(--color-surface-3)',
        },
        brand: {
          violet: 'var(--color-brand-violet)',
          magenta: 'var(--color-brand-magenta)',
          blue: 'var(--color-brand-blue)',
        },
        semantic: {
          success: 'var(--color-semantic-success)',
          warning: 'var(--color-semantic-warning)',
          error: 'var(--color-semantic-error)',
          info: 'var(--color-semantic-info)',
        },
        text: {
          primary: 'var(--color-text-primary)',
          secondary: 'var(--color-text-secondary)',
          muted: 'var(--color-text-muted)',
        },

        /* shadcn/ui CSS variable colors */
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
      },
      borderRadius: {
        'card': '24px',
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      boxShadow: {
        'glow-violet': 'var(--glow-violet)',
        'glow-magenta': 'var(--glow-magenta)',
        'glow-blue': 'var(--glow-blue)',
      },
      backgroundImage: {
        'gradient-cta': 'var(--gradient-cta)',
        'gradient-secondary': 'var(--gradient-secondary)',
        'gradient-ai': 'var(--gradient-ai)',
      },
      transitionDuration: {
        'micro': '150ms',
        'complex': '400ms',
        'page': '500ms',
      },
      keyframes: {
        'accordion-down': {
          from: { height: '0' },
          to: { height: 'var(--radix-accordion-content-height)' },
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: '0' },
        },
        'fade-in': {
          from: { opacity: '0', transform: 'translateY(8px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-in-right': {
          from: { opacity: '0', transform: 'translateX(16px)' },
          to: { opacity: '1', transform: 'translateX(0)' },
        },
      },
      animation: {
        'accordion-down': 'accordion-down 0.2s ease-out',
        'accordion-up': 'accordion-up 0.2s ease-out',
        'fade-in': 'fade-in 0.5s cubic-bezier(0.4, 0, 0.2, 1)',
        'slide-in-right': 'slide-in-right 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
}
