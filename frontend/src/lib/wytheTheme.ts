'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';

export type AppearanceMode = 'system' | 'dark' | 'light';
export type PolygonRenderMode = 'simple' | 'atomic';
export type WythePresetId =
  | 'stratified'
  | 'abyssal'
  | 'bioluminescent'
  | 'blueprint'
  | 'woodland'
  | 'custom';

export interface WythePaletteColors {
  bg: string;
  sceneBg: string;
  inquiry: string;
  display: string;
  manipulate: string;
  truth: string;
  warn: string;
  danger: string;
  muted: string;
}

interface PresetPair {
  label: string;
  dark: WythePaletteColors;
  light: WythePaletteColors;
}

const STORAGE_KEY = 'wythe.appearance.v1';

export const WYTHE_PRESETS: Record<Exclude<WythePresetId, 'custom'>, PresetPair> = {
  stratified: {
    label: 'Stratified 3-Tier (Default)',
    dark: {
      bg: '#0B111E',
      sceneBg: '#070B12',
      inquiry: '#F4F7FB',
      display: '#60A5FA',
      manipulate: '#38BDF8',
      truth: '#2DD4BF',
      warn: '#F59E0B',
      danger: '#F43F5E',
      muted: '#64748B',
    },
    light: {
      bg: '#F5F7FA',
      sceneBg: '#EEF2F7',
      inquiry: '#0F172A',
      display: '#2563EB',
      manipulate: '#0284C7',
      truth: '#0D9488',
      warn: '#D97706',
      danger: '#E11D48',
      muted: '#64748B',
    },
  },
  abyssal: {
    label: 'Abyssal Teal & Cobalt',
    dark: {
      bg: '#0A101D',
      sceneBg: '#060A13',
      inquiry: '#2DD4BF',
      display: '#3B82F6',
      manipulate: '#38BDF8',
      truth: '#14B8A6',
      warn: '#F59E0B',
      danger: '#F43F5E',
      muted: '#64748B',
    },
    light: {
      bg: '#F2F6FA',
      sceneBg: '#E9EFF6',
      inquiry: '#0F766E',
      display: '#1D4ED8',
      manipulate: '#0369A1',
      truth: '#0F766E',
      warn: '#B45309',
      danger: '#BE123C',
      muted: '#64748B',
    },
  },
  bioluminescent: {
    label: 'Bioluminescent Mint',
    dark: {
      bg: '#090F1A',
      sceneBg: '#060A12',
      inquiry: '#5EEAD4',
      display: '#38BDF8',
      manipulate: '#2DD4BF',
      truth: '#10B981',
      warn: '#FBBF24',
      danger: '#FB7185',
      muted: '#64748B',
    },
    light: {
      bg: '#F3F5F2',
      sceneBg: '#EAEFEA',
      inquiry: '#0F766E',
      display: '#1E40AF',
      manipulate: '#0E7490',
      truth: '#047857',
      warn: '#B45309',
      danger: '#BE123C',
      muted: '#64748B',
    },
  },
  blueprint: {
    label: 'Blueprint & Brass',
    dark: {
      bg: '#0D1626',
      sceneBg: '#080E1A',
      inquiry: '#FBBF24',
      display: '#93C5FD',
      manipulate: '#60A5FA',
      truth: '#38BDF8',
      warn: '#F59E0B',
      danger: '#F43F5E',
      muted: '#64748B',
    },
    light: {
      bg: '#F6F1E6',
      sceneBg: '#EFE9DA',
      inquiry: '#B45309',
      display: '#1E3A5F',
      manipulate: '#1D4ED8',
      truth: '#0369A1',
      warn: '#B45309',
      danger: '#BE123C',
      muted: '#64748B',
    },
  },
  woodland: {
    label: 'Woodland Slate',
    dark: {
      bg: '#1B2E36',
      sceneBg: '#101B20',
      inquiry: '#F4EFE4',
      display: '#8AB4C4',
      manipulate: '#6FA3B8',
      truth: '#5DAE8B',
      warn: '#D99B26',
      danger: '#E05A47',
      muted: '#7B8D96',
    },
    light: {
      bg: '#F4EFE4',
      sceneBg: '#ECE5D5',
      inquiry: '#1D3540',
      display: '#426878',
      manipulate: '#2F5969',
      truth: '#3B6B4E',
      warn: '#A16207',
      danger: '#B91C1C',
      muted: '#6B7280',
    },
  },
};

interface StoredState {
  appearance: AppearanceMode;
  preset: WythePresetId;
  polygonMode: PolygonRenderMode;
  customDark: WythePaletteColors;
  customLight: WythePaletteColors;
}

const DEFAULT_STATE: StoredState = {
  appearance: 'system',
  preset: 'stratified',
  polygonMode: 'atomic',
  customDark: WYTHE_PRESETS.stratified.dark,
  customLight: WYTHE_PRESETS.stratified.light,
};

export function useWytheAppearance() {
  const [state, setState] = useState<StoredState>(DEFAULT_STATE);
  const [sysLight, setSysLight] = useState(false);

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as Partial<StoredState>;
        setState((prev) => ({
          appearance: parsed.appearance ?? prev.appearance,
          preset: parsed.preset ?? prev.preset,
          polygonMode: parsed.polygonMode ?? prev.polygonMode,
          customDark: { ...prev.customDark, ...(parsed.customDark ?? {}) },
          customLight: { ...prev.customLight, ...(parsed.customLight ?? {}) },
        }));
      }
    } catch {
      // ignore storage errors
    }
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    setSysLight(mq.matches);
    const onChange = (ev: MediaQueryListEvent) => setSysLight(ev.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  const resolvedPolarity: 'dark' | 'light' =
    state.appearance === 'system' ? (sysLight ? 'light' : 'dark') : state.appearance;

  useEffect(() => {
    document.documentElement.dataset.theme = resolvedPolarity;
    document.documentElement.classList.toggle('dark', resolvedPolarity === 'dark');
  }, [resolvedPolarity]);

  const persist = useCallback((updater: (prev: StoredState) => StoredState) => {
    setState((prev) => {
      const next = updater(prev);
      try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } catch {
        // ignore storage errors
      }
      return next;
    });
  }, []);

  const palette: WythePaletteColors = useMemo(() => {
    if (state.preset === 'custom') {
      return resolvedPolarity === 'light' ? state.customLight : state.customDark;
    }
    return WYTHE_PRESETS[state.preset][resolvedPolarity];
  }, [state.preset, state.customDark, state.customLight, resolvedPolarity]);

  const updateCustomColor = useCallback(
    (key: keyof Pick<WythePaletteColors, 'inquiry' | 'display' | 'manipulate' | 'truth'>, hex: string) => {
      persist((prev) => {
        const basePair = prev.preset === 'custom'
          ? { dark: prev.customDark, light: prev.customLight }
          : WYTHE_PRESETS[prev.preset];
        return {
          ...prev,
          preset: 'custom',
          customDark: resolvedPolarity === 'dark' ? { ...basePair.dark, [key]: hex } : basePair.dark,
          customLight: resolvedPolarity === 'light' ? { ...basePair.light, [key]: hex } : basePair.light,
        };
      });
    },
    [persist, resolvedPolarity],
  );

  return {
    appearance: state.appearance,
    resolvedPolarity,
    preset: state.preset,
    polygonMode: state.polygonMode,
    palette,
    setAppearance: (appearance: AppearanceMode) => persist((p) => ({ ...p, appearance })),
    setPreset: (preset: WythePresetId) => persist((p) => ({ ...p, preset })),
    setPolygonMode: (polygonMode: PolygonRenderMode) => persist((p) => ({ ...p, polygonMode })),
    updateCustomColor,
    resetPalette: () =>
      persist((p) => ({
        ...p,
        preset: 'stratified',
        customDark: WYTHE_PRESETS.stratified.dark,
        customLight: WYTHE_PRESETS.stratified.light,
      })),
  };
}
