/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        critical: '#ff4444',
        high: '#ff8c00',
        medium: '#ffd700',
        low: '#00cc88',
        safe: '#00cc88',
        'brand-cyan': '#00bcd4',
        'brand-blue': '#1e40af',
        'bg-dark': '#0a0f1a',
        'bg-card': '#0d1117',
        'bg-surface': '#161b22',
        'border-dark': '#21262d',
      },
    },
  },
  plugins: [],
};
