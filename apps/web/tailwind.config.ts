import type { Config } from "tailwindcss";

const config: Config = {
    content: [
        "./app/**/*.{js,ts,jsx,tsx,mdx}",
        "./components/**/*.{js,ts,jsx,tsx,mdx}",
    ],
    theme: {
        extend: {
            colors: {
                terminal: {
                    // SANDEVISTAN Exact Palette
                    bg: "#0c0c0c",           // Deep black background
                    bgLight: "#141414",      // Slightly lighter for cards
                    text: "#5f9ea0",         // Cadet blue/cyan - main text
                    textBright: "#7ec8ca",   // Brighter cyan for highlights
                    accent: "#5f9ea0",       // Same cyan for accents
                    red: "#c94c4c",          // Coral/salmon red
                    redBright: "#e05555",    // Brighter red
                    dim: "#4a4a4a",          // Dark gray for secondary
                    border: "#2a2a2a",       // Dark border
                }
            },
            fontFamily: {
                mono: [
                    "IBM Plex Mono",
                    "Source Code Pro",
                    "ui-monospace",
                    "Menlo",
                    "Monaco",
                    "Consolas",
                    "monospace"
                ],
            },
        },
    },
    plugins: [],
};
export default config;
