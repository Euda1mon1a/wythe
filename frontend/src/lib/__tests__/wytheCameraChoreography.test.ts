import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { ViewportCommandEvent } from '@/api/atlas';
import {
  applyIncomingViewportEvent,
  createInitialAgentCameraState,
  resumeAgentCameraFollow,
} from '../wytheCameraChoreography';
import { evaluateIncomingViewportCommand } from '../wytheInvestigationSession';

function buildQueuedProbeEvent(overrides?: Partial<ViewportCommandEvent>): ViewportCommandEvent {
  return {
    seq: 1,
    issued_at: '2026-11-16T00:00:00Z',
    permalink: '/#target=audit&session=session-a&focus=t%3Aitems&preset=iso_overview&zoom=1',
    delivery_state: 'paused_by_human',
    applied_by_client_ids: [],
    command: {
      command_id: 'resume-probe',
      target_slug: 'audit',
      session_id: 'session-a',
      focus_node_ids: ['t:items'],
      highlight_edge_ids: [],
      expected_evidence_revision: 'revision-old',
      expires_at: '2026-11-16T00:01:00Z',
      zoom_stratum: 1,
      framing_preset: 'iso_overview',
      caption: 'Focus items table',
      tour_keyframes: [],
      chronicle_frames: [],
    },
    ...overrides,
  };
}

test('F7 (#107): expired queued command is rejected on SSE and resume without promotion to activeEvent', () => {
  const event = buildQueuedProbeEvent();
  const baseParams = {
    event,
    source: 'sse' as const,
    activeTargetSlug: 'audit',
    activeSessionId: 'session-a',
    clientId: 'browser-a',
    followState: 'paused' as const,
    currentEvidenceRevisionId: 'revision-old',
    nowMs: Date.parse('2026-11-16T00:00:00Z'),
  };

  const initial = evaluateIncomingViewportCommand(baseParams);
  assert.equal(initial.action, 'queue_while_paused');
  assert.equal(initial.receiptOutcome, 'paused_by_human');

  const queued = applyIncomingViewportEvent(createInitialAgentCameraState('paused'), event);
  assert.equal(queued.shouldMoveCamera, false);
  assert.equal(queued.state.pendingEventWhilePaused?.command.command_id, 'resume-probe');
  assert.equal(queued.state.activeEvent?.command.command_id, 'resume-probe');

  const expiredMs = Date.parse('2026-11-16T00:02:00Z');
  const sseExpired = evaluateIncomingViewportCommand({
    ...baseParams,
    followState: 'following',
    nowMs: expiredMs,
  });
  assert.equal(sseExpired.action, 'reject');
  assert.equal(sseExpired.shouldMoveCamera, false);
  assert.equal(sseExpired.receiptOutcome, 'rejected');
  assert.equal(sseExpired.reason, 'expired');
  assert.equal(sseExpired.markAcked, true);

  const resumeExpired = evaluateIncomingViewportCommand({
    ...baseParams,
    source: 'resume',
    followState: 'following',
    nowMs: expiredMs,
  });
  assert.equal(resumeExpired.action, 'reject');
  assert.equal(resumeExpired.shouldMoveCamera, false);
  assert.equal(resumeExpired.receiptOutcome, 'rejected');
  assert.equal(resumeExpired.reason, 'expired');
  assert.equal(resumeExpired.markAcked, true);

  const reloadExpired = evaluateIncomingViewportCommand({
    ...baseParams,
    source: 'initial_state',
    followState: 'following',
    nowMs: expiredMs,
  });
  assert.equal(reloadExpired.action, 'ignore');
  assert.equal(reloadExpired.receiptOutcome, null);
  assert.equal(reloadExpired.reason, 'expired');

  const resumed = resumeAgentCameraFollow(queued.state, {
    nowMs: expiredMs,
    currentEvidenceRevisionId: 'revision-old',
    activeTargetSlug: 'audit',
    activeSessionId: 'session-a',
    clientId: 'browser-a',
  });
  assert.equal(resumed.followMode, 'following');
  assert.equal(resumed.liveFollowing, true);
  assert.equal(resumed.pendingEventWhilePaused, null);
  assert.equal(resumed.activeEvent, null);
});

test('F7 (#107): stale expected_evidence_revision and mismatched scope are rejected on resume while valid queued command promotes', () => {
  const event = buildQueuedProbeEvent({ seq: 2 });
  const priorApplied = buildQueuedProbeEvent({
    seq: 1,
    delivery_state: 'applied_by_browser',
    command: {
      ...event.command,
      command_id: 'prior-valid-cmd',
      expected_evidence_revision: 'revision-new',
      expires_at: '2026-11-16T00:10:00Z',
    },
  });
  const pausedWithPrior = applyIncomingViewportEvent(
    {
      ...createInitialAgentCameraState('paused'),
      activeEvent: priorApplied,
    },
    event,
  );
  const validTimeMs = Date.parse('2026-11-16T00:00:30Z');

  const resumeStaleDecision = evaluateIncomingViewportCommand({
    event,
    source: 'resume',
    activeTargetSlug: 'audit',
    activeSessionId: 'session-a',
    clientId: 'browser-a',
    followState: 'following',
    currentEvidenceRevisionId: 'revision-new',
    nowMs: validTimeMs,
  });
  assert.equal(resumeStaleDecision.action, 'reject_stale');
  assert.equal(resumeStaleDecision.shouldMoveCamera, false);
  assert.equal(resumeStaleDecision.receiptOutcome, 'stale_revision');
  assert.equal(resumeStaleDecision.markAcked, true);

  const resumedStale = resumeAgentCameraFollow(pausedWithPrior.state, {
    nowMs: validTimeMs,
    currentEvidenceRevisionId: 'revision-new',
    activeTargetSlug: 'audit',
    activeSessionId: 'session-a',
  });
  assert.equal(resumedStale.followMode, 'following');
  assert.equal(resumedStale.pendingEventWhilePaused, null);
  assert.equal(resumedStale.activeEvent?.command.command_id, 'prior-valid-cmd');

  const wrongSessionResumed = resumeAgentCameraFollow(
    applyIncomingViewportEvent(createInitialAgentCameraState('paused'), event).state,
    {
      nowMs: validTimeMs,
      currentEvidenceRevisionId: 'revision-old',
      activeTargetSlug: 'audit',
      activeSessionId: 'session-b',
    },
  );
  assert.equal(wrongSessionResumed.activeEvent, null);
  assert.equal(wrongSessionResumed.pendingEventWhilePaused, null);

  const validResumed = resumeAgentCameraFollow(
    applyIncomingViewportEvent(createInitialAgentCameraState('paused'), event).state,
    {
      nowMs: validTimeMs,
      currentEvidenceRevisionId: 'revision-old',
      activeTargetSlug: 'audit',
      activeSessionId: 'session-a',
    },
  );
  assert.equal(validResumed.followMode, 'following');
  assert.equal(validResumed.liveFollowing, true);
  assert.equal(validResumed.pendingEventWhilePaused, null);
  assert.equal(validResumed.activeEvent?.command.command_id, 'resume-probe');
});
