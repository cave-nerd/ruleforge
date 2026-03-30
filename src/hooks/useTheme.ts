import { useEffect, useState } from "react";

export type ThemeMode = "light" | "dark" | "system";

export type AccentColor =
  | "ocean"
  | "indigo"
  | "emerald"
  | "amber"
  | "rose"
  | "violet";

// ── Accent palettes (RGB triplets for Tailwind opacity modifier support) ─────

interface AccentPalette {
  label: string;
  /** Hex preview swatch shown in the picker */
  swatch: string;
  /** CSS custom-property values (space-separated RGB) keyed by shade */
  shades: Record<string, string>;
}

export const ACCENT_PALETTES: Record<AccentColor, AccentPalette> = {
  ocean: {
    label: "Ocean",
    swatch: "#0ea5e9",
    shades: {
      "--brand-300": "125 211 252",
      "--brand-400": "56 189 248",
      "--brand-500": "14 165 233",
      "--brand-600": "2 132 199",
    },
  },
  indigo: {
    label: "Indigo",
    swatch: "#6366f1",
    shades: {
      "--brand-300": "165 180 252",
      "--brand-400": "129 140 248",
      "--brand-500": "99 102 241",
      "--brand-600": "79 70 229",
    },
  },
  emerald: {
    label: "Emerald",
    swatch: "#10b981",
    shades: {
      "--brand-300": "110 231 183",
      "--brand-400": "52 211 153",
      "--brand-500": "16 185 129",
      "--brand-600": "5 150 105",
    },
  },
  amber: {
    label: "Amber",
    swatch: "#f59e0b",
    shades: {
      "--brand-300": "252 211 77",
      "--brand-400": "251 191 36",
      "--brand-500": "245 158 11",
      "--brand-600": "217 119 6",
    },
  },
  rose: {
    label: "Rose",
    swatch: "#f43f5e",
    shades: {
      "--brand-300": "253 164 175",
      "--brand-400": "251 113 133",
      "--brand-500": "244 63 94",
      "--brand-600": "225 29 72",
    },
  },
  violet: {
    label: "Violet",
    swatch: "#8b5cf6",
    shades: {
      "--brand-300": "196 181 253",
      "--brand-400": "167 139 250",
      "--brand-500": "139 92 246",
      "--brand-600": "124 58 237",
    },
  },
};

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useTheme() {
  const [mode, setMode] = useState<ThemeMode>(() => {
    return (localStorage.getItem("rf-theme-mode") as ThemeMode) ?? "system";
  });

  const [accent, setAccent] = useState<AccentColor>(() => {
    return (localStorage.getItem("rf-accent") as AccentColor) ?? "ocean";
  });

  const [resolved, setResolved] = useState<"light" | "dark">("dark");

  // ── Apply dark/light class ────────────────────────────────────────────────

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");

    function apply() {
      const isDark =
        mode === "dark" || (mode === "system" && media.matches);
      setResolved(isDark ? "dark" : "light");
      document.documentElement.classList.toggle("dark", isDark);
    }

    apply();
    const handler = () => {
      if (mode === "system") apply();
    };
    media.addEventListener("change", handler);
    return () => media.removeEventListener("change", handler);
  }, [mode]);

  // ── Apply accent CSS variables ────────────────────────────────────────────

  useEffect(() => {
    const palette = ACCENT_PALETTES[accent] ?? ACCENT_PALETTES.ocean;
    const root = document.documentElement;
    for (const [prop, value] of Object.entries(palette.shades)) {
      root.style.setProperty(prop, value);
    }
  }, [accent]);

  // ── Setters that persist ──────────────────────────────────────────────────

  function changeMode(next: ThemeMode) {
    setMode(next);
    localStorage.setItem("rf-theme-mode", next);
  }

  function changeAccent(next: AccentColor) {
    setAccent(next);
    localStorage.setItem("rf-accent", next);
  }

  return { mode, resolved, accent, changeMode, changeAccent };
}
