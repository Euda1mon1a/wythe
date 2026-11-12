'use client';

import { useEffect, useId, useRef, useState } from 'react';
import { Palette, RotateCcw, Sparkles } from 'lucide-react';
import {
  WYTHE_PRESETS,
  type AppearanceMode,
  type PolygonRenderMode,
  type WythePaletteColors,
  type WythePresetId,
} from '@/lib/wytheTheme';

const Q_PATH =
  'M 25.0 -10.4 C 31.8 -10.4 36.2 -5.8 36.2 0.3 C 36.2 6.4 31.8 10.5 26.2 10.5 C 21.8 10.5 19.8 7.0 18.2 3.0 C 17.2 0.7 16.4 0.0 15.2 0.0';
const ANGLES = [-90, 30, 150] as const;

export function WytheMark({
  palette,
  size = 26,
}: {
  palette: WythePaletteColors;
  size?: number;
}) {
  const maskId = useId().replace(/:/g, '');
  const barColors = [palette.display, palette.manipulate, palette.truth];
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      aria-hidden="true"
      className="shrink-0 rounded-[6px] shadow-sm"
    >
      <defs>
        <mask id={maskId} maskUnits="userSpaceOnUse" x="0" y="0" width="100" height="100">
          <rect width="100" height="100" fill="white" />
          {ANGLES.map((ang) => (
            <g key={ang} transform={`translate(50 53.5) scale(0.74) rotate(${ang})`}>
              <path
                d={Q_PATH}
                fill="none"
                stroke="black"
                strokeWidth="10.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <circle cx="8.4" cy="0" r="6.0" fill="black" />
            </g>
          ))}
        </mask>
      </defs>
      <rect width="100" height="100" rx="22" fill={palette.bg} />
      <g mask={`url(#${maskId})`}>
        {ANGLES.map((ang, idx) => (
          <g key={ang} transform={`translate(50 53.5) rotate(${ang})`}>
            <rect x="22.8" y="-23.5" width="11.0" height="47.0" rx="3.0" fill={barColors[idx]} />
          </g>
        ))}
      </g>
      {ANGLES.map((ang) => (
        <g key={ang} transform={`translate(50 53.5) scale(0.74) rotate(${ang})`}>
          <path
            d={Q_PATH}
            fill="none"
            stroke={palette.inquiry}
            strokeWidth="5.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <circle cx="8.4" cy="0" r="3.5" fill={palette.inquiry} />
        </g>
      ))}
    </svg>
  );
}

interface WytheAppearanceControlProps {
  appearance: AppearanceMode;
  preset: WythePresetId;
  polygonMode: PolygonRenderMode;
  palette: WythePaletteColors;
  onChangeAppearance: (mode: AppearanceMode) => void;
  onChangePreset: (preset: WythePresetId) => void;
  onChangePolygonMode: (mode: PolygonRenderMode) => void;
  onChangeCustomColor: (
    key: 'inquiry' | 'display' | 'manipulate' | 'truth',
    hex: string,
  ) => void;
  onResetPalette: () => void;
}

export function WytheAppearanceControl({
  appearance,
  preset,
  polygonMode,
  palette,
  onChangeAppearance,
  onChangePreset,
  onChangePolygonMode,
  onChangeCustomColor,
  onResetPalette,
}: WytheAppearanceControlProps) {
  const [open, setOpen] = useState(false);
  const [alignLeft, setAlignLeft] = useState(false);
  const popRef = useRef<HTMLDivElement>(null);

  const toggleOpen = () => {
    if (!open && popRef.current) {
      const rect = popRef.current.getBoundingClientRect();
      setAlignLeft(rect.left < 300);
    }
    setOpen((v) => !v);
  };

  useEffect(() => {
    if (!open) return;
    const onDocDown = (ev: MouseEvent) => {
      if (popRef.current && !popRef.current.contains(ev.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDocDown);
    window.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocDown);
      window.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div ref={popRef} className="relative flex items-center gap-1.5 font-mono text-xs">
      <button
        type="button"
        onClick={() => onChangePolygonMode(polygonMode === 'atomic' ? 'simple' : 'atomic')}
        aria-label="Toggle 3D polygon mode between Atomic Wythe breathing lattice and Simple solids"
        title="Switch 3D meshes between Atomic Wythe breathing lattice and Simple solids"
        className={`flex items-center gap-1.5 border px-2.5 py-1 ${
          polygonMode === 'atomic'
            ? 'border-teal-500/50 bg-teal-500/15 text-teal-300'
            : 'border-slate-700 bg-slate-900 text-slate-300 hover:text-slate-100'
        }`}
      >
        <Sparkles className="h-3.5 w-3.5" />
        {polygonMode === 'atomic' ? 'Polygons: Atomic' : 'Polygons: Simple'}
      </button>

      <button
        type="button"
        aria-expanded={open}
        aria-label="Open theme polarity and custom color settings"
        onClick={toggleOpen}
        className="flex items-center gap-1.5 border border-slate-700 bg-slate-900 px-2.5 py-1 text-slate-200 hover:border-teal-400 hover:text-teal-300"
      >
        <Palette className="h-3.5 w-3.5" />
        Theme
      </button>

      {open && (
        <div
          className={`absolute ${alignLeft ? 'left-0' : 'right-0'} top-9 z-40 w-72 space-y-3 border border-slate-700 bg-slate-950 p-3.5 shadow-2xl`}
        >
          <div className="space-y-1">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-300">
              Polarity (Row 1 / Row 2)
            </div>
            <div className="grid grid-cols-3 border border-slate-800 bg-slate-900 p-0.5">
              {(['system', 'dark', 'light'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => onChangeAppearance(m)}
                  className={`py-1 uppercase ${
                    appearance === m
                      ? 'bg-teal-500/20 font-semibold text-teal-300'
                      : 'text-slate-300 hover:text-slate-100'
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor="wythe-preset-select" className="block text-[11px] font-semibold uppercase tracking-wider text-slate-300">
              Colorway Preset
            </label>
            <select
              id="wythe-preset-select"
              value={preset}
              onChange={(e) => onChangePreset(e.target.value as WythePresetId)}
              className="w-full border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-100"
            >
              {(Object.keys(WYTHE_PRESETS) as Array<Exclude<WythePresetId, 'custom'>>).map((k) => (
                <option key={k} value={k}>
                  {WYTHE_PRESETS[k].label}
                </option>
              ))}
              <option value="custom">Custom User Palette</option>
            </select>
          </div>

          <div className="space-y-1.5 border-t border-slate-800 pt-2.5">
            <div className="flex items-center justify-between text-[11px] text-slate-300">
              <span className="font-semibold uppercase tracking-wider">Custom Colors</span>
              <button
                type="button"
                onClick={onResetPalette}
                className="flex items-center gap-1 text-slate-300 hover:text-teal-300"
              >
                <RotateCcw className="h-3 w-3" /> Reset
              </button>
            </div>
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              {(
                [
                  ['inquiry', 'Why / Dots'],
                  ['display', 'Display Bar'],
                  ['manipulate', 'Backend Bar'],
                  ['truth', 'Truth Bar'],
                ] as const
              ).map(([key, label]) => (
                <label key={key} className="flex items-center gap-2 border border-slate-800 bg-slate-900 px-2 py-1 text-slate-200">
                  <input
                    type="color"
                    aria-label={`${label} color`}
                    value={palette[key]}
                    onChange={(e) => onChangeCustomColor(key, e.target.value)}
                    className="h-4 w-5 cursor-pointer border-0 bg-transparent p-0"
                  />
                  <span className="truncate">{label}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
