'use client';

import { useEffect, useRef } from 'react';

const TABBABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled]):not([tabindex="-1"])',
  'input:not([disabled]):not([tabindex="-1"])',
  'select:not([disabled]):not([tabindex="-1"])',
  'textarea:not([disabled]):not([tabindex="-1"])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ');

export interface UseDialogFocusTrapOptions {
  open: boolean;
  containerRef: { readonly current: HTMLElement | null };
  initialFocusRef?: { readonly current: HTMLElement | null };
  onClose: () => void;
  closeOnEscape?: boolean;
}

export function computeWrappedFocusIndex(
  count: number,
  currentIndex: number,
  shiftKey: boolean,
): number {
  if (count <= 0) return -1;
  if (currentIndex < 0 || currentIndex >= count) {
    return shiftKey ? count - 1 : 0;
  }
  return (currentIndex + (shiftKey ? -1 : 1) + count) % count;
}

function getVisibleTabbableElements(container: HTMLElement): HTMLElement[] {
  const candidates = Array.from(container.querySelectorAll<HTMLElement>(TABBABLE_SELECTOR));
  return candidates.filter((el) => el.offsetParent !== null || el === document.activeElement);
}

export function useDialogFocusTrap({
  open,
  containerRef,
  initialFocusRef,
  onClose,
  closeOnEscape = true,
}: UseDialogFocusTrapOptions): void {
  const containerRefRef = useRef(containerRef);
  const initialFocusRefRef = useRef(initialFocusRef);
  const onCloseRef = useRef(onClose);
  const closeOnEscapeRef = useRef(closeOnEscape);

  useEffect(() => {
    containerRefRef.current = containerRef;
    initialFocusRefRef.current = initialFocusRef;
    onCloseRef.current = onClose;
    closeOnEscapeRef.current = closeOnEscape;
  });

  useEffect(() => {
    if (!open || typeof document === 'undefined' || typeof window === 'undefined') {
      return;
    }

    const previouslyFocused = document.activeElement as HTMLElement | null;

    const rafId = window.requestAnimationFrame(() => {
      const container = containerRefRef.current.current;
      if (!container) return;

      const preferred = initialFocusRefRef.current?.current;
      if (preferred && container.contains(preferred) && !preferred.hasAttribute('disabled')) {
        preferred.focus();
        return;
      }

      const tabbables = getVisibleTabbableElements(container);
      if (tabbables.length > 0) {
        tabbables[0].focus();
        return;
      }

      if (container.getAttribute('tabindex') === null) {
        container.setAttribute('tabindex', '-1');
      }
      container.focus();
    });

    const handleKeyDown = (e: KeyboardEvent) => {
      const container = containerRefRef.current.current;
      if (!container) return;

      const activeElement = document.activeElement as HTMLElement | null;
      const myDialog = container.closest('[role="dialog"]') ?? container;
      const activeDialog = activeElement?.closest('[role="dialog"]') ?? null;
      if (activeDialog && activeDialog !== myDialog) return;

      if (e.key === 'Escape') {
        if (closeOnEscapeRef.current !== false) {
          e.preventDefault();
          e.stopPropagation();
          onCloseRef.current();
        }
        return;
      }

      if (e.key !== 'Tab' || e.metaKey || e.ctrlKey || e.altKey) return;

      const tabbables = getVisibleTabbableElements(container);
      e.preventDefault();
      e.stopPropagation();

      if (tabbables.length === 0) {
        if (container.getAttribute('tabindex') === null) {
          container.setAttribute('tabindex', '-1');
        }
        container.focus();
        return;
      }

      const currentIndex = activeElement ? tabbables.indexOf(activeElement) : -1;
      const nextIndex = computeWrappedFocusIndex(tabbables.length, currentIndex, e.shiftKey);
      if (nextIndex >= 0 && nextIndex < tabbables.length) {
        tabbables[nextIndex].focus();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      window.cancelAnimationFrame(rafId);
      document.removeEventListener('keydown', handleKeyDown);
      if (
        previouslyFocused &&
        previouslyFocused.isConnected &&
        typeof previouslyFocused.focus === 'function'
      ) {
        previouslyFocused.focus();
      }
    };
  }, [open]);
}
