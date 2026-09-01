package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// The verify-evidence surface is the service's second, purpose-scoped store:
// abuse evidence for the ANONYMOUS public document-verification endpoint —
// who drove it and with what — so a provider-side complaint about quota abuse
// is answerable. It is deliberately separate from the GDPR access log above
// (different purpose, different lawful basis, its own shorter retention) and
// lives in its own `verify_audit` schema; only the service binary and its
// role are shared.

// VerifyEvent is one abuse-evidence event from the public verification
// surface. It carries request metadata and the upload's hash — never any
// document content.
type VerifyEvent struct {
	// TS is when the verification request happened.
	TS time.Time
	// IP + UserAgent identify the anonymous caller as far as the edge saw it.
	IP        string
	UserAgent string
	// SizeBytes + SHA256 describe the uploaded file without holding it.
	SizeBytes int64
	SHA256    string
	// Verdict is the normalized outcome, or a typed reject/error marker.
	Verdict string
	// CorrelationID joins the request across service logs; SessionID is the
	// provider-side transient validation session the upload was processed in.
	CorrelationID string
	SessionID     string
	// SourceService is the authenticated caller identity (derived, never from
	// the event body).
	SourceService string
}

// VerifySweepResult reports one retention sweep of the verify-evidence store.
type VerifySweepResult struct {
	Cutoff string
	Purged int64
}

// AppendVerifyEvent implements Store via verify_audit.record_event.
func (p *Postgres) AppendVerifyEvent(ctx context.Context, ev *VerifyEvent) (string, error) {
	data, err := p.call(ctx, "verify_audit.record_event", map[string]any{
		"event": map[string]any{
			"ts":            ev.TS.UTC().Format(time.RFC3339Nano),
			"ip":            ev.IP,
			"userAgent":     ev.UserAgent,
			"sizeBytes":     ev.SizeBytes,
			"sha256":        ev.SHA256,
			"verdict":       ev.Verdict,
			"correlationId": ev.CorrelationID,
			"sessionId":     ev.SessionID,
		},
		"source_service": ev.SourceService,
	})
	if err != nil {
		return "", err
	}

	var res struct {
		EventID string `json:"eventId"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return "", fmt.Errorf("store: record_event: decode: %w", err)
	}

	return res.EventID, nil
}

// SweepVerifyExpired implements Store via verify_audit.sweep_retention.
func (p *Postgres) SweepVerifyExpired(ctx context.Context, retentionDays int) (*VerifySweepResult, error) {
	data, err := p.call(ctx, "verify_audit.sweep_retention", map[string]any{
		"retention_days": retentionDays,
	})
	if err != nil {
		return nil, err
	}

	var res struct {
		Cutoff string `json:"cutoff"`
		Purged int64  `json:"purged"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: sweep_retention: decode: %w", err)
	}

	return &VerifySweepResult{Cutoff: res.Cutoff, Purged: res.Purged}, nil
}

// AppendVerifyEvent implements Store in memory.
func (m *Memory) AppendVerifyEvent(_ context.Context, ev *VerifyEvent) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *ev
	id := ulid.Make().String()
	m.verifyEvents = append(m.verifyEvents, &cp)

	return id, nil
}

// SweepVerifyExpired implements Store in memory.
func (m *Memory) SweepVerifyExpired(_ context.Context, retentionDays int) (*VerifySweepResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	kept := m.verifyEvents[:0]
	var purged int64
	for _, ev := range m.verifyEvents {
		if ev.TS.Before(cutoff) {
			purged++

			continue
		}
		kept = append(kept, ev)
	}
	m.verifyEvents = kept

	return &VerifySweepResult{Cutoff: cutoff.Format(time.RFC3339), Purged: purged}, nil
}

// VerifyEvents returns a copy of the stored events (test use).
func (m *Memory) VerifyEvents() []*VerifyEvent {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*VerifyEvent, len(m.verifyEvents))
	copy(out, m.verifyEvents)

	return out
}
