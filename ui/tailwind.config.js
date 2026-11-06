/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,html}"],
  theme: {
    extend: {
      colors: {
        pixel: {
          bg: "#121316",
          surface: "#1E1F25",
          surfaceVariant: "#2A2C34",
          surfaceHigh: "#353742",
          primary: "#A8C7FA",
          onPrimary: "#062E6F",
          primaryContainer: "#004A77",
          onPrimaryContainer: "#C2E7FF",
          accentGreen: "#C4EDD0",
          onAccentGreen: "#0A3818",
          accentRed: "#F2B8B5",
          onAccentRed: "#601410",
          textPrimary: "#E3E2E6",
          textSecondary: "#C4C6D0",
          textOutline: "#8E9099",
        },
      },
      borderRadius: { "4xl": "2rem" },
    },
  },
  plugins: [],
};
