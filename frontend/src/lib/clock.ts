/**
 * Centralized timestamp formatting utilities for Truth Atlas UI.
 * All date/instant formatting goes through this module so UI components never
 * construct ad-hoc Date instances or slice UTC ISO strings.
 */

export function formatObservedInstant(isoString: string | null | undefined): string {
  if (!isoString) return '—';
  const parsed = new Date(isoString);
  if (Number.isNaN(parsed.getTime())) return isoString;
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZoneName: 'short',
  }).format(parsed);
}

export function formatCalendarDay(dateOnly: string | null | undefined): string {
  if (!dateOnly) return '—';
  const parts = dateOnly.split('-');
  if (parts.length !== 3) return dateOnly;
  return `${parts[0]}-${parts[1]}-${parts[2]}`;
}
