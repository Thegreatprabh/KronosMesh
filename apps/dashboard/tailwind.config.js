/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        abyss: '#070b14',
        panel: '#0d1321',
        edge: '#1c2740',
        neon: '#22d3ee',
        mint: '#34d399',
        amber: '#fbbf24',
        danger: '#f87171',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
    },
  },
  plugins: [],
};
