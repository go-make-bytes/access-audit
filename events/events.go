// Package events emits the access-audit service's own NIS2-audit security events
// through go-sec-events, from the request path and from background work alike —
// the retention Tasker has no request, and the security library serves both.
//
// NOTE: this is the service's *operational* telemetry (auth denials, integrity
// checks, retention runs). The GDPR-audit access RECORDS the service stores are a
// different thing entirely — they arrive from go-gdpr-audit producers and are
// persisted, not emitted here.
package events

import (
	"context"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"
)

// Event types emitted by the access-audit service.
const (
	EventAuthzDenied       = "authz.denied" // platform-standard type
	EventIntegrityMismatch = "access_audit.integrity_mismatch"
	EventCheckpointWritten = "access_audit.checkpoint_written"
	EventRetentionPurge    = "access_audit.retention_purge"
	EventLegalHoldChanged  = "access_audit.legal_hold_changed"
)

// Emitter emits security events with or without a request context.
type Emitter struct {
	sec *secevents.Emitter
	log *zap.Logger
}

// New returns an Emitter delivering both paths through the go-sec-events log
// sink. The sink is built with the service logger because background work has no
// request whose logger it could borrow; log is also where a failure to emit is
// reported when there is no request to report it against.
func New(log *zap.Logger) *Emitter {
	if log == nil {
		log = zap.NewNop()
	}

	return &Emitter{sec: secevents.NewEmitter(secevents.NewLogSinkFor(log)), log: log}
}

// Emit delivers one security event. ctx may be nil for background work.
func (e *Emitter) Emit(ctx *azugo.Context, eventType string, sev secevents.Severity, outcome broker.Outcome, attrs map[string]any) {
	if e == nil {
		return
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs[secevents.AttrSeverity] = string(sev)

	ev := &broker.Envelope{
		EventType:  eventType,
		Categories: []broker.Category{broker.CategorySecurity},
		Outcome:    outcome,
		Attributes: attrs,
	}

	if ctx != nil {
		// The request path carries the correlation id + trace id, so a failure to
		// emit is joinable to the request it happened on.
		if err := e.sec.Emit(ctx, ev); err != nil {
			ctx.Log().Error("security event emission failed", zap.String("event_type", eventType), zap.Error(err))
		}

		return
	}

	// Background work — the retention Tasker — has no request. Same tagging,
	// sanitizing, stamping and rendered shape; only the correlation ids are absent,
	// because there is no request to take them from.
	if err := e.sec.EmitBackground(context.Background(), ev); err != nil {
		e.log.Error("security event emission failed", zap.String("event_type", eventType), zap.Error(err))
	}
}

// AuthzDenied records a scope/authZ denial on an access-audit endpoint.
func (e *Emitter) AuthzDenied(ctx *azugo.Context, requiredScope, actorID, path string) {
	e.Emit(ctx, EventAuthzDenied, secevents.SeverityWarning, broker.OutcomeDenied, map[string]any{
		"required_scope": requiredScope,
		"actor_id":       actorID,
		"path":           path,
	})
}

// IntegrityMismatch records that a verify pass found a broken seal or checkpoint
// — a high-severity tamper signal.
func (e *Emitter) IntegrityMismatch(ctx *azugo.Context, scope, detail string) {
	e.Emit(ctx, EventIntegrityMismatch, secevents.SeverityHigh, broker.OutcomeFailure, map[string]any{
		"scope":  scope,
		"detail": detail,
	})
}

// CheckpointWritten records that the retention sweep sealed a period checkpoint
// (background; info).
func (e *Emitter) CheckpointWritten(period string, count int) {
	e.Emit(nil, EventCheckpointWritten, secevents.SeverityInfo, broker.OutcomeSuccess, map[string]any{
		"period": period,
		"count":  count,
	})
}

// RetentionPurge records a retention purge run (background). Anything retained
// under legal hold raises it to a warning so it is visible.
func (e *Emitter) RetentionPurge(cutoff string, purged, retainedUnderHold int64) {
	sev := secevents.SeverityInfo
	if retainedUnderHold > 0 {
		sev = secevents.SeverityWarning
	}
	e.Emit(nil, EventRetentionPurge, sev, broker.OutcomeSuccess, map[string]any{
		"cutoff":              cutoff,
		"purged":              purged,
		"retained_under_hold": retainedUnderHold,
	})
}

// LegalHoldChanged records a privileged legal-hold placement/clearance.
func (e *Emitter) LegalHoldChanged(ctx *azugo.Context, subject string, hold bool, actorID string) {
	e.Emit(ctx, EventLegalHoldChanged, secevents.SeverityWarning, broker.OutcomeSuccess, map[string]any{
		"subject":  subject,
		"hold":     hold,
		"actor_id": actorID,
	})
}
