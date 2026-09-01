package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// Memory is a non-durable in-memory Store for tests and local development. It
// mirrors the Postgres backend's semantics: idempotent append on event id,
// subject-indexed reads, per-period seal listing, write-once checkpoints, legal
// holds and period purge. It is safe for concurrent use.
type Memory struct {
	mu           sync.Mutex
	byEventID    map[string]*Record
	records      []*Record // insertion order; Seq is index+1
	checkpoints  map[string]*Checkpoint
	holds        map[string]bool
	verifyEvents []*VerifyEvent
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		byEventID:   make(map[string]*Record),
		checkpoints: make(map[string]*Checkpoint),
		holds:       make(map[string]bool),
	}
}

// Append implements Store.
func (m *Memory) Append(_ context.Context, rec *Record) (*AppendResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	eid := rec.Envelope.EventID
	if existing, ok := m.byEventID[eid]; ok {
		return &AppendResult{RecordID: existing.RowID, EventID: eid, Duplicate: true}, nil
	}

	cp := *rec
	cp.RowID = ulid.Make().String()
	cp.Seq = int64(len(m.records) + 1)

	m.records = append(m.records, &cp)
	m.byEventID[eid] = &cp

	return &AppendResult{RecordID: cp.RowID, EventID: eid, Duplicate: false}, nil
}

// BySubject implements Store.
func (m *Memory) BySubject(_ context.Context, subject string, from, to time.Time, limit int) ([]*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limit <= 0 {
		limit = 1000
	}

	out := make([]*Record, 0)
	for _, r := range m.records {
		if !containsString(r.Envelope.DataSubjects, subject) {
			continue
		}
		if !from.IsZero() && r.Envelope.OccurredAt.Before(from) {
			continue
		}
		if !to.IsZero() && r.Envelope.OccurredAt.After(to) {
			continue
		}

		rc := *r
		out = append(out, &rc)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Envelope.OccurredAt.Equal(out[j].Envelope.OccurredAt) {
			return out[i].Seq < out[j].Seq
		}

		return out[i].Envelope.OccurredAt.Before(out[j].Envelope.OccurredAt)
	})

	if len(out) > limit {
		out = out[:limit]
	}

	return out, nil
}

// SealsForPeriod implements Store.
func (m *Memory) SealsForPeriod(_ context.Context, period string) ([]string, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	type es struct {
		eventID string
		seal    string
	}

	rows := make([]es, 0)
	for _, r := range m.records {
		if Period(r.Envelope.OccurredAt) == period {
			rows = append(rows, es{eventID: r.Envelope.EventID, seal: r.Seal})
		}
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].eventID < rows[j].eventID })

	seals := make([]string, len(rows))
	for i, r := range rows {
		seals[i] = r.seal
	}

	return seals, len(seals), nil
}

// PendingCheckpointPeriods implements Store.
func (m *Memory) PendingCheckpointPeriods(_ context.Context, before string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[string]bool)
	for _, r := range m.records {
		p := Period(r.Envelope.OccurredAt)
		// YYYY-MM-DD strings sort chronologically.
		if p >= before {
			continue
		}
		if _, ok := m.checkpoints[p]; ok {
			continue
		}
		seen[p] = true
	}

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)

	return out, nil
}

// SaveCheckpoint implements Store.
func (m *Memory) SaveCheckpoint(_ context.Context, cp *Checkpoint) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.checkpoints[cp.Period]; ok {
		return false, nil
	}

	stored := *cp
	if stored.SealedAt.IsZero() {
		stored.SealedAt = time.Now().UTC()
	}
	m.checkpoints[cp.Period] = &stored

	return true, nil
}

// LoadCheckpoint implements Store.
func (m *Memory) LoadCheckpoint(_ context.Context, period string) (*Checkpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp, ok := m.checkpoints[period]
	if !ok {
		return nil, nil
	}

	out := *cp

	return &out, nil
}

// SetLegalHold implements Store.
func (m *Memory) SetLegalHold(_ context.Context, subject, _, _ string, hold bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if hold {
		m.holds[subject] = true
	} else {
		delete(m.holds, subject)
	}

	return nil
}

// PurgeExpired implements Store.
func (m *Memory) PurgeExpired(_ context.Context, cutoff string) (*PurgeResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	kept := make([]*Record, 0, len(m.records))
	var purged, retained int64

	for _, r := range m.records {
		period := Period(r.Envelope.OccurredAt)
		// YYYY-MM-DD strings sort chronologically.
		if period >= cutoff {
			kept = append(kept, r)
			continue
		}
		if m.heldLocked(r.Envelope.DataSubjects) {
			retained++
			kept = append(kept, r)
			continue
		}

		purged++
		delete(m.byEventID, r.Envelope.EventID)
	}

	m.records = kept

	return &PurgeResult{Cutoff: cutoff, Purged: purged, RetainedUnderHold: retained}, nil
}

// Ping implements Store.
func (m *Memory) Ping(context.Context) error { return nil }

// Close implements Store.
func (m *Memory) Close() {}

func (m *Memory) heldLocked(subjects []string) bool {
	for _, s := range subjects {
		if m.holds[s] {
			return true
		}
	}

	return false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}

	return false
}
