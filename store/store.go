// Package store persists the append-only, subject-indexed GDPR access log
// (GDPR-audit). The platform backend is PostgreSQL reached ONLY through the
// `access_audit` schema's SECURITY DEFINER procedures under an EXECUTE-only role
// (authbyte-db/access-audit); an in-memory backend exists for tests. No backend
// exposes raw table access — every operation is a procedure call.
package store

import (
	"context"
	"time"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// Record is one persisted access record: the producer's envelope plus the
// server-held seal and the server-derived annotations.
type Record struct {
	// RowID is the store-assigned ULID primary key (populated on read/append).
	RowID string
	// Envelope is the producer's record, stored verbatim as the sealed content.
	Envelope broker.Envelope
	// Seal is the hex HMAC-SHA256 over the envelope's canonical bytes.
	Seal string
	// Seq is the DB-assigned monotonic sequence (read side only).
	Seq int64
	// SourceService is the authenticated caller identity (derived, never from
	// the record body).
	SourceService string
	// System is the optional tenant/system dimension.
	System string
}

// AppendResult reports the outcome of an append.
type AppendResult struct {
	RecordID  string
	EventID   string
	Duplicate bool
}

// Checkpoint is a per-retention-period sealed integrity attestation.
type Checkpoint struct {
	Period   string // YYYY-MM-DD (first day of the month, UTC)
	RowCount int64
	Seal     string
	SealedAt time.Time
}

// PurgeResult reports a retention purge.
type PurgeResult struct {
	Cutoff            string
	Purged            int64
	RetainedUnderHold int64
}

// Store is the audit persistence contract: the GDPR access log (mapping 1:1
// onto the access_audit schema procedures) plus the purpose-scoped
// verify-evidence surface (the verify_audit schema — see verify.go for the
// purpose split).
type Store interface {
	// Append persists rec, idempotent on rec.Envelope.EventID; the returned
	// Duplicate is true when that event id was already stored (outbox retry).
	Append(ctx context.Context, rec *Record) (*AppendResult, error)
	// BySubject returns every record whose data_subjects include subject, for
	// DSAR (Art. 15). from/to bound occurred_at (zero = unbounded); limit caps
	// the result (0 = backend default).
	BySubject(ctx context.Context, subject string, from, to time.Time, limit int) ([]*Record, error)
	// SealsForPeriod returns a retention period's per-row seals ordered by
	// event_id, plus the count, for checkpoint computation/verification.
	SealsForPeriod(ctx context.Context, period string) (seals []string, count int, err error)
	// PendingCheckpointPeriods returns the distinct retention periods strictly
	// before `before` (YYYY-MM-DD, normally the first of the current month) that
	// hold records but have no checkpoint yet — the closed periods the retention
	// sweep must seal before purging.
	PendingCheckpointPeriods(ctx context.Context, before string) ([]string, error)
	// SaveCheckpoint persists cp (write-once per period); created is false when a
	// checkpoint already existed for the period.
	SaveCheckpoint(ctx context.Context, cp *Checkpoint) (created bool, err error)
	// LoadCheckpoint returns the stored checkpoint for period, or (nil, nil).
	LoadCheckpoint(ctx context.Context, period string) (*Checkpoint, error)
	// SetLegalHold places (hold=true) or clears (hold=false) a legal hold on a
	// data subject; held subjects' records are skipped by PurgeExpired.
	SetLegalHold(ctx context.Context, subject, reason, placedBy string, hold bool) error
	// PurgeExpired deletes records in retention periods strictly older than
	// cutoff (YYYY-MM-DD), except records touching a held subject.
	PurgeExpired(ctx context.Context, cutoff string) (*PurgeResult, error)
	// AppendVerifyEvent appends one verify abuse-evidence event (the
	// verify_audit surface) and returns its store id.
	AppendVerifyEvent(ctx context.Context, ev *VerifyEvent) (string, error)
	// SweepVerifyExpired deletes verify events older than the retention window.
	SweepVerifyExpired(ctx context.Context, retentionDays int) (*VerifySweepResult, error)
	// Ping verifies backend connectivity for readiness checks.
	Ping(ctx context.Context) error
	// Close releases backend resources.
	Close()
}

// Period returns the retention-period bucket (first day of the month, UTC) for t
// as the YYYY-MM-DD string the procedures expect.
func Period(t time.Time) string {
	y, m, _ := t.UTC().Date()

	return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
}
