// Package seal computes and verifies the tamper-evidence the access log relies
// on: a per-row HMAC-SHA256 SEAL over each record's
// canonical bytes, and a per-retention-period CHECKPOINT over a period's ordered
// row seals. Both use a key held only in memory (sourced from Vault) — it is
// never persisted alongside the records it protects, so a party with table-only
// access cannot forge a matching seal.
//
// Unlike eIDAS-audit's continuous prev_hash→hash chain, this scheme is
// purge-compatible: dropping an old retention period does not invalidate the
// seals or checkpoints of the periods that remain.
package seal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// Sealer holds the HMAC key and produces/verifies seals and checkpoints. It is
// safe for concurrent use.
type Sealer struct {
	key []byte
}

// New returns a Sealer over a copy of key. key must be non-empty.
func New(key []byte) (*Sealer, error) {
	if len(key) == 0 {
		return nil, errors.New("seal: empty key")
	}

	k := make([]byte, len(key))
	copy(k, key)

	return &Sealer{key: k}, nil
}

// canonicalView is the fixed-order projection of the content-bearing envelope
// fields the seal is computed over. It deliberately EXCLUDES the chained-sink
// fields (prev_hash/hash) and any DB-assigned sequence: the seal attests the
// producer's record content, not anything the store adds.
//
// The canonical bytes must reproduce after a JSON/jsonb round-trip, so values
// are normalised deterministically (data_subjects + categories sorted,
// occurred_at as RFC3339Nano UTC, attributes serialised with encoding/json's
// sorted map keys). The envelope contract bounds attribute values to identifiers and
// short operational metadata, so they survive the round-trip.
type canonicalView struct {
	EventID      string           `json:"event_id"`
	OccurredAt   string           `json:"occurred_at"`
	Categories   []string         `json:"category"`
	EventType    string           `json:"event_type"`
	Actor        *broker.Actor    `json:"actor,omitempty"`
	DataSubjects []string         `json:"data_subjects,omitempty"`
	Resource     *broker.Resource `json:"resource,omitempty"`
	Operation    string           `json:"operation,omitempty"`
	LawfulBasis  string           `json:"lawful_basis,omitempty"`
	Purpose      string           `json:"purpose,omitempty"`
	Outcome      string           `json:"outcome"`
	IP           string           `json:"ip,omitempty"`
	Device       string           `json:"device,omitempty"`
	Attributes   map[string]any   `json:"attributes,omitempty"`
}

// canonical builds the deterministic byte form of e.
func canonical(e *broker.Envelope) ([]byte, error) {
	if e == nil {
		return nil, errors.New("seal: nil envelope")
	}

	subs := append([]string(nil), e.DataSubjects...)
	sort.Strings(subs)

	cats := make([]string, len(e.Categories))
	for i, c := range e.Categories {
		cats[i] = string(c)
	}
	sort.Strings(cats)

	v := canonicalView{
		EventID:      e.EventID,
		OccurredAt:   e.OccurredAt.UTC().Format(time.RFC3339Nano),
		Categories:   cats,
		EventType:    e.EventType,
		Actor:        e.Actor,
		DataSubjects: subs,
		Resource:     e.Resource,
		Operation:    string(e.Operation),
		LawfulBasis:  e.LawfulBasis,
		Purpose:      e.Purpose,
		Outcome:      string(e.Outcome),
		IP:           e.IP,
		Device:       e.Device,
		Attributes:   e.Attributes,
	}

	return json.Marshal(v)
}

// Seal returns the hex HMAC-SHA256 seal of e's canonical bytes.
func (s *Sealer) Seal(e *broker.Envelope) (string, error) {
	b, err := canonical(e)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(b)

	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Verify reports whether want is the valid seal for e (constant-time compare).
func (s *Sealer) Verify(e *broker.Envelope, want string) bool {
	got, err := s.Seal(e)
	if err != nil {
		return false
	}

	return hmac.Equal([]byte(got), []byte(want))
}

// Checkpoint returns the hex HMAC-SHA256 over a retention period's ordered row
// seals and row count. seals must be in the deterministic order the store
// returns them (by event_id) so the value reproduces at verification time. A
// deleted/added row changes both the count and the seal list, so the checkpoint
// no longer matches — which is what detects tampering within a retained period.
func (s *Sealer) Checkpoint(seals []string, count int) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = fmt.Fprintf(mac, "n=%d\n", count)

	for _, x := range seals {
		_, _ = mac.Write([]byte(x))
		_, _ = mac.Write([]byte{'\n'})
	}

	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyCheckpoint reports whether want matches the checkpoint recomputed from
// seals/count (constant-time compare).
func (s *Sealer) VerifyCheckpoint(seals []string, count int, want string) bool {
	got := s.Checkpoint(seals, count)

	return hmac.Equal([]byte(got), []byte(want))
}
