package store

import (
	"context"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// compile-time check that Memory satisfies Store.
var _ Store = (*Memory)(nil)

func rec(eid string, occurred time.Time, subjects ...string) *Record {
	return &Record{
		Envelope: broker.Envelope{
			EventID:      eid,
			OccurredAt:   occurred,
			Categories:   []broker.Category{broker.CategoryGDPRAccess},
			EventType:    "document.access",
			Outcome:      broker.OutcomeSuccess,
			DataSubjects: subjects,
		},
		Seal: "seal-" + eid,
	}
}

func TestMemoryAppendIdempotent(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	r := rec("e1", time.Now().UTC(), "subA")
	res1, err := m.Append(ctx, r)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(res1.Duplicate))

	res2, err := m.Append(ctx, r)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(res2.Duplicate))
	qt.Check(t, qt.Equals(res2.RecordID, res1.RecordID))
}

func TestMemoryBySubject(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

	_, _ = m.Append(ctx, rec("e1", base, "subA"))
	_, _ = m.Append(ctx, rec("e2", base.Add(time.Hour), "subA", "subB"))
	_, _ = m.Append(ctx, rec("e3", base.Add(2*time.Hour), "subC"))

	got, err := m.BySubject(ctx, "subA", time.Time{}, time.Time{}, 0)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(got), 2))
	// Ordered by occurred_at.
	qt.Check(t, qt.Equals(got[0].Envelope.EventID, "e1"))
	qt.Check(t, qt.Equals(got[1].Envelope.EventID, "e2"))

	// Time-bounded.
	bounded, err := m.BySubject(ctx, "subA", base.Add(30*time.Minute), time.Time{}, 0)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(bounded), 1))
	qt.Check(t, qt.Equals(bounded[0].Envelope.EventID, "e2"))
}

func TestMemorySealsForPeriodOrdered(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

	_, _ = m.Append(ctx, rec("ebbb", base, "s"))
	_, _ = m.Append(ctx, rec("eaaa", base.Add(time.Hour), "s"))

	seals, count, err := m.SealsForPeriod(ctx, Period(base))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(count, 2))
	// Ordered by event_id: eaaa before ebbb.
	qt.Check(t, qt.DeepEquals(seals, []string{"seal-eaaa", "seal-ebbb"}))
}

func TestMemoryCheckpointWriteOnce(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	created, err := m.SaveCheckpoint(ctx, &Checkpoint{Period: "2026-05-01", RowCount: 2, Seal: "cp"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(created))

	created2, err := m.SaveCheckpoint(ctx, &Checkpoint{Period: "2026-05-01", RowCount: 2, Seal: "cp"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(created2))

	cp, err := m.LoadCheckpoint(ctx, "2026-05-01")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(cp.Seal, "cp"))
}

func TestMemoryPurgeSkipsLegalHold(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	old := time.Date(2025, 1, 15, 9, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 5, 15, 9, 0, 0, 0, time.UTC)

	_, _ = m.Append(ctx, rec("old-held", old, "held"))
	_, _ = m.Append(ctx, rec("old-free", old, "free"))
	_, _ = m.Append(ctx, rec("recent", recent, "free"))

	qt.Assert(t, qt.IsNil(m.SetLegalHold(ctx, "held", "case-42", "svc:admin", true)))

	// Keep 2026-01 onward; purge older.
	res, err := m.PurgeExpired(ctx, "2026-01-01")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Purged, int64(1)))            // old-free
	qt.Check(t, qt.Equals(res.RetainedUnderHold, int64(1))) // old-held

	// old-free gone; old-held + recent remain.
	heldRecs, err := m.BySubject(ctx, "held", time.Time{}, time.Time{}, 0)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(heldRecs), 1))

	freeRecs, err := m.BySubject(ctx, "free", time.Time{}, time.Time{}, 0)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(freeRecs), 1))
	qt.Check(t, qt.Equals(freeRecs[0].Envelope.EventID, "recent"))
}

func TestMemoryPendingCheckpointPeriods(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	_, _ = m.Append(ctx, rec("a", time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), "s"))
	_, _ = m.Append(ctx, rec("b", time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC), "s"))

	pending, err := m.PendingCheckpointPeriods(ctx, "2026-06-01")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(pending, []string{"2026-03-01", "2026-04-01"}))

	// Once a period is checkpointed it drops out.
	_, _ = m.SaveCheckpoint(ctx, &Checkpoint{Period: "2026-03-01", RowCount: 1, Seal: "cp"})
	pending2, err := m.PendingCheckpointPeriods(ctx, "2026-06-01")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(pending2, []string{"2026-04-01"}))
}
