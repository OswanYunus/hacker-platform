import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#0F1115",
          900: "#151924",
          800: "#1D2230",
          700: "#2A3041",
          600: "#3B4255",
        },
        paper: {
          50: "#FAFAF8",
          100: "#F3F3F0",
          200: "#E7E6E1",
        },
        accent: {
          DEFAULT: "#B5752F",
          dim: "#8C5B24",
          soft: "#F0E3D0",
        },
        severity: {
          critical: "#A4221B",
          high: "#B5541A",
          medium: "#946C0D",
          low: "#345C82",
          info: "#5B6472",
        },
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      borderRadius: {
        sm: "3px",
        DEFAULT: "4px",
        md: "6px",
      },
    },
  },
  plugins: [],
};
export default config;
