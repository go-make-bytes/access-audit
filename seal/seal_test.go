package seal

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-platform-kit/broker"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func sampleEnvelope() *broker.Envelope {
	return &broker.Envelope{
		EventID:      "evt-doc-1",
		OccurredAt:   time.Date(2026, 5, 10, 12, 0, 0, 123456000, time.UTC),
		Categories:   []broker.Category{broker.CategoryGDPRAccess},
		EventType:    "document.access",
		Actor:        &broker.Actor{ID: "svc:document", Type: "service"},
		DataSubjects: []string{"id-2", "id-1"},
		Resource:     &broker.Resource{Type: "document", ID: "doc-1"},
		Operation:    broker.OpRead,
		LawfulBasis:  "contract",
		Purpose:      "signing",
		Outcome:      broker.OutcomeSuccess,
		Attributes:   map[string]any{"channel": "interactive", "count": float64(3)},
	}
}

func TestNewRejectsEmptyKey(t *testing.T) {
	_, err := New(nil)
	qt.Check(t, qt.IsNotNil(err))
}

func TestSealDeterministicAndVerify(t *testing.T) {
	s, err := New(testKey)
	qt.Assert(t, qt.IsNil(err))

	e := sampleEnvelope()
	h1, err := s.Seal(e)
	qt.Assert(t, qt.IsNil(err))
	h2, err := s.Seal(e)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(h1, h2))
	qt.Check(t, qt.IsTrue(s.Verify(e, h1)))

	// Tampering with any sealed field breaks the seal.
	tampered := sampleEnvelope()
	tampered.Outcome = broker.OutcomeDenied
	qt.Check(t, qt.IsFalse(s.Verify(tampered, h1)))
}

// TestSealSurvivesJSONRoundTrip is the property the verify path depends on: the
// seal recomputed from the stored (marshalled) envelope must match the seal
// computed at append time.
func TestSealSurvivesJSONRoundTrip(t *testing.T) {
	s, err := New(testKey)
	qt.Assert(t, qt.IsNil(err))

	e := sampleEnvelope()
	want, err := s.Seal(e)
	qt.Assert(t, qt.IsNil(err))

	raw, err := json.Marshal(e)
	qt.Assert(t, qt.IsNil(err))

	var back broker.Envelope
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &back)))

	qt.Check(t, qt.IsTrue(s.Verify(&back, want)))
}

func TestSealSubjectOrderIndependent(t *testing.T) {
	s, err := New(testKey)
	qt.Assert(t, qt.IsNil(err))

	a := sampleEnvelope()
	a.DataSubjects = []string{"id-1", "id-2"}
	b := sampleEnvelope()
	b.DataSubjects = []string{"id-2", "id-1"}

	ha, err := s.Seal(a)
	qt.Assert(t, qt.IsNil(err))
	hb, err := s.Seal(b)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(ha, hb))
}

func TestSealKeyMatters(t *testing.T) {
	s1, err := New(testKey)
	qt.Assert(t, qt.IsNil(err))
	s2, err := New([]byte("a-different-key-aaaaaaaaaaaaaaaaaa"))
	qt.Assert(t, qt.IsNil(err))

	e := sampleEnvelope()
	h1, err := s1.Seal(e)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.IsFalse(s2.Verify(e, h1)))
}

func TestCheckpointDetectsAddRemove(t *testing.T) {
	s, err := New(testKey)
	qt.Assert(t, qt.IsNil(err))

	cp := s.Checkpoint([]string{"a", "b", "c"}, 3)
	qt.Check(t, qt.IsTrue(s.VerifyCheckpoint([]string{"a", "b", "c"}, 3, cp)))
	// A removed row.
	qt.Check(t, qt.IsFalse(s.VerifyCheckpoint([]string{"a", "b"}, 2, cp)))
	// An added row.
	qt.Check(t, qt.IsFalse(s.VerifyCheckpoint([]string{"a", "b", "c", "d"}, 4, cp)))
	// A changed row seal.
	qt.Check(t, qt.IsFalse(s.VerifyCheckpoint([]string{"a", "b", "X"}, 3, cp)))
}
