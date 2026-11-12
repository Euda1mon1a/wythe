'use client';

import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { AlertTriangle, Command, CornerDownLeft, FolderGit2, Layers, Search, Terminal, X } from 'lucide-react';
import type { AtlasNode, BoundaryFinding, TargetProjectRead } from '@/api/atlas';
import {
  buildPaletteItems,
  parsePaletteQuery,
  type PaletteItem,
  type PaletteMode,
  type QuickActionDef,
} from '@/lib/wytheCommands';

interface CommandPaletteProps {
  open: boolean;
  initialQuery?: string;
  actions: QuickActionDef[];
  nodes: AtlasNode[];
  findings: BoundaryFinding[];
  targets: TargetProjectRead[];
  activeSlug: string;
  onClose: () => void;
  onSelectNode: (nodeId: string) => void;
  onSelectFinding: (finding: BoundaryFinding) => void;
  onSelectTarget: (slug: string) => void;
}

const BADGE_TONE_CLASS: Record<NonNullable<PaletteItem['badgeTone']>, string> = {
  teal: 'border-teal-500/40 bg-teal-500/15 text-teal-300',
  sky: 'border-sky-500/40 bg-sky-500/15 text-sky-300',
  amber: 'border-amber-500/40 bg-amber-500/15 text-amber-300',
  rose: 'border-rose-500/40 bg-rose-500/15 text-rose-300',
  slate: 'border-slate-700 bg-slate-900 text-slate-300',
};

export function CommandPalette({
  open,
  initialQuery = '',
  actions,
  nodes,
  findings,
  targets,
  activeSlug,
  onClose,
  onSelectNode,
  onSelectFinding,
  onSelectTarget,
}: CommandPaletteProps) {
  const [query, setQuery] = useState(initialQuery);
  const [filterOverride, setFilterOverride] = useState<PaletteMode | null>(null);
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const rowRefs = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    if (!open) return;
    setQuery(initialQuery);
    setFilterOverride(null);
    setActiveIndex(0);
    const id = window.requestAnimationFrame(() => inputRef.current?.focus());
    return () => window.cancelAnimationFrame(id);
  }, [open, initialQuery]);

  const items = useMemo(
    () =>
      buildPaletteItems({
        rawQuery: query,
        filterOverride,
        actions,
        nodes,
        findings,
        targets,
        activeSlug,
        onSelectNode: (nodeId) => {
          onSelectNode(nodeId);
          onClose();
        },
        onSelectFinding: (f) => {
          onSelectFinding(f);
          onClose();
        },
        onSelectTarget: (slug) => {
          onSelectTarget(slug);
          onClose();
        },
      }),
    [query, filterOverride, actions, nodes, findings, targets, activeSlug, onSelectNode, onSelectFinding, onSelectTarget, onClose],
  );

  useEffect(() => {
    setActiveIndex(0);
  }, [query, filterOverride]);

  useEffect(() => {
    const el = rowRefs.current[activeIndex];
    el?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);

  if (!open) return null;

  const effectiveMode = filterOverride ?? parsePaletteQuery(query).mode;

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      onClose();
      return;
    }
    if (items.length === 0) return;
    if (e.key === 'ArrowDown' || (e.ctrlKey && e.key.toLowerCase() === 'n')) {
      e.preventDefault();
      setActiveIndex((prev) => (prev + 1) % items.length);
    } else if (e.key === 'ArrowUp' || (e.ctrlKey && e.key.toLowerCase() === 'p')) {
      e.preventDefault();
      setActiveIndex((prev) => (prev - 1 + items.length) % items.length);
    } else if (e.key === 'Home') {
      e.preventDefault();
      setActiveIndex(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      setActiveIndex(items.length - 1);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const target = items[activeIndex];
      if (target) target.onSelect();
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Wythe Command Palette"
      onKeyDown={handleKeyDown}
      className="fixed inset-0 z-50 flex items-start justify-center bg-slate-950/75 px-4 pt-[10vh] backdrop-blur-sm"
    >
      <button
        type="button"
        aria-label="Close command palette backdrop"
        tabIndex={-1}
        onClick={onClose}
        className="fixed inset-0 h-full w-full cursor-default bg-transparent"
      />
      <div className="relative z-10 w-full max-w-2xl border border-slate-700 bg-slate-950 font-mono shadow-2xl">
        {/* Search Input Row */}
        <div className="flex items-center gap-2.5 border-b border-slate-800 px-3.5 py-2.5">
          <Search className="h-4 w-4 shrink-0 text-teal-400" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search commands, 3-tier nodes, findings, or targets"
            placeholder="Type command or node… (> actions, @ nodes, @col:, @http:, @sub:, ! flagged, # targets)"
            className="w-full bg-transparent text-xs text-slate-100 placeholder-slate-400 focus:outline-none"
          />
          {query && (
            <button
              type="button"
              aria-label="Clear palette query"
              onClick={() => setQuery('')}
              className="text-slate-300 hover:text-slate-100"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
          <button
            type="button"
            aria-label="Close command palette"
            onClick={onClose}
            className="border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-300 hover:text-slate-100"
          >
            ESC
          </button>
        </div>

        {/* Mode Filter Bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 bg-slate-900/60 px-3.5 py-1.5 text-[11px]">
          <div className="flex flex-wrap items-center gap-1">
            {(
              [
                ['all', 'All'],
                ['actions', '> Actions'],
                ['nodes', `@ Nodes (${nodes.length})`],
                ['findings', `! Flagged (${findings.length})`],
                ['targets', `# Targets (${targets.length})`],
              ] as const
            ).map(([m, label]) => (
              <button
                key={m}
                type="button"
                onClick={() => setFilterOverride(filterOverride === m ? null : m)}
                className={`border px-2 py-0.5 ${
                  effectiveMode === m
                    ? 'border-teal-500/50 bg-teal-500/15 text-teal-300'
                    : 'border-slate-800 bg-slate-950 text-slate-300 hover:text-slate-100'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          <span className="text-[10px] text-slate-300">{items.length} matches</span>
        </div>

        {/* Results List */}
        <div role="listbox" aria-label="Command palette results" className="max-h-[52vh] overflow-y-auto p-1.5">
          {items.length === 0 ? (
            <div className="px-4 py-8 text-center text-xs text-slate-300">
              No matching commands, 3-tier nodes, or findings for &ldquo;{query}&rdquo;.
            </div>
          ) : (
            items.map((item, idx) => {
              const active = idx === activeIndex;
              const prevGroup = idx > 0 ? items[idx - 1].group : null;
              return (
                <div key={item.key}>
                  {item.group !== prevGroup && (
                    <div className="px-2.5 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-slate-300">
                      {item.group}
                    </div>
                  )}
                  <button
                    ref={(el) => {
                      rowRefs.current[idx] = el;
                    }}
                    type="button"
                    role="option"
                    aria-selected={active}
                    onMouseEnter={() => setActiveIndex(idx)}
                    onClick={item.onSelect}
                    className={`flex w-full items-center justify-between gap-3 px-2.5 py-2 text-left text-xs ${
                      active
                        ? 'border-l-2 border-teal-400 bg-teal-500/15 text-slate-100'
                        : 'border-l-2 border-transparent text-slate-200 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex min-w-0 items-center gap-2.5">
                      {item.kind === 'action' && <Terminal className="h-3.5 w-3.5 shrink-0 text-teal-300" />}
                      {item.kind === 'node' && <Layers className="h-3.5 w-3.5 shrink-0 text-sky-300" />}
                      {item.kind === 'finding' && <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-300" />}
                      {item.kind === 'target' && <FolderGit2 className="h-3.5 w-3.5 shrink-0 text-teal-300" />}
                      <div className="min-w-0">
                        <div className="truncate font-medium">{item.label}</div>
                        <div className="truncate text-[11px] text-slate-300">{item.subtitle}</div>
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      {item.badge && (
                        <span
                          className={`border px-1.5 py-0.5 text-[10px] uppercase ${
                            BADGE_TONE_CLASS[item.badgeTone ?? 'slate']
                          }`}
                        >
                          {item.badge}
                        </span>
                      )}
                      {item.shortcut && (
                        <kbd className="border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-200">
                          {item.shortcut}
                        </kbd>
                      )}
                      {active && <CornerDownLeft className="h-3 w-3 text-teal-300" />}
                    </div>
                  </button>
                </div>
              );
            })
          )}
        </div>

        {/* Power-User Chord Footer */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 bg-slate-900/80 px-3.5 py-2 text-[10px] text-slate-300">
          <span className="flex flex-wrap items-center gap-1.5">
            <Command className="h-3 w-3 text-teal-300" />
            Keys: <kbd className="border border-slate-700 bg-slate-950 px-1">F</kbd> Fullscreen ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">⇧F</kbd> OS Full ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">1–4</kbd> Views ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">T</kbd> Stratum ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">G</kbd> Flagged ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">C</kbd> Cone ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">[ ]</kbd> Step ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">V</kbd> Lens ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">L</kbd> Layout ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">B</kbd> Blast ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">M</kbd> Center ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">P</kbd> Polygons ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">D</kbd> Theme ·{' '}
            <kbd className="border border-slate-700 bg-slate-950 px-1">R</kbd> Rescan
          </span>
          <span>↑↓ Navigate · ↵ Run</span>
        </div>
      </div>
    </div>
  );
}
