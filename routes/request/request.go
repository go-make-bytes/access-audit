// Package request holds the access-audit HTTP request DTOs and their validation.
package request

import (
	"strings"

	"azugo.io/azugo"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// AccessRecord is the POST /v1/access-records body: the
// broker.Envelope (embedded so its exact JSON shape is preserved) that a
// go-gdpr-audit producer posts, tagged gdpr_access.
type AccessRecord struct {
	broker.Envelope
}

// knownBases are the accepted GDPR Art. 6 lawful bases (empty is allowed — not
// every access carries one explicitly).
var knownBases = map[string]bool{
	"contract":            true,
	"legal_obligation":    true,
	"consent":             true,
	"legitimate_interest": true,
	"public_task":         true,
	"vital_interest":      true,
}

// Validate implements azugo.Validator — called automatically by ctx.Body.JSON().
// It enforces the minimum a GDPR-audit record must carry and defends the
// data_subjects contract (pseudonymous internal refs only).
func (r *AccessRecord) Validate(_ *azugo.Context) error {
	e := &r.Envelope

	if e.EventID == "" {
		return azugo.ParamRequiredError{Name: "event_id"}
	}
	if e.OccurredAt.IsZero() {
		return azugo.ParamRequiredError{Name: "occurred_at"}
	}
	if e.EventType == "" {
		return azugo.ParamRequiredError{Name: "event_type"}
	}
	if e.Outcome == "" {
		return azugo.ParamRequiredError{Name: "outcome"}
	}
	if !hasCategory(e.Categories, broker.CategoryGDPRAccess) {
		return azugo.BadRequestError{Description: "category must include gdpr_access"}
	}
	if len(e.DataSubjects) == 0 {
		return azugo.ParamRequiredError{Name: "data_subjects"}
	}
	for _, s := range e.DataSubjects {
		if !validSubjectRef(s) {
			return azugo.ParamInvalidError{Name: "data_subjects", Tag: "pseudonymous_ref"}
		}
	}
	if e.LawfulBasis != "" && !knownBases[e.LawfulBasis] {
		return azugo.ParamInvalidError{Name: "lawful_basis", Tag: "oneof"}
	}

	return nil
}

func hasCategory(cats []broker.Category, want broker.Category) bool {
	for _, c := range cats {
		if c == want {
			return true
		}
	}

	return false
}

// validSubjectRef rejects values that are obviously NOT pseudonymous internal
// references — national identifiers, e-mails, names with spaces — defending the
// data_subjects contract (these values flow into the store and a DSAR
// index; identifying values must never land here).
func validSubjectRef(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	if strings.ContainsAny(s, "@ \t\r\n") {
		return false
	}

	return !looksLikePersonalCode(s)
}

// looksLikePersonalCode flags an 11-digit Latvian-style personal code
// (optionally with a single dash), e.g. "XXXXXX-XXXXX".
func looksLikePersonalCode(s string) bool {
	digits := 0
	dashes := 0
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == '-':
			dashes++
		default:
			return false
		}
	}

	return digits == 11 && dashes <= 1
}

// maxAttrValueLen bounds a string attribute value; longer values are truncated
// (mirrors go-sec-events / go-gdpr-audit — operational metadata, not narratives).
const maxAttrValueLen = 256

// forbiddenAttrKeys are attribute-key fragments that would put document content
// or free-text PII into the stored record. The producer strips these too; this
// is defense-in-depth at the sink.
var forbiddenAttrKeys = []string{
	"document_bytes", "content_bytes", "file_bytes", "free_text",
	"note", "comment", "body", "payload", "email", "phone",
}

// Sanitize strips content-bearing attribute keys and truncates string attribute
// values on e in place. The envelope is otherwise stored verbatim.
func Sanitize(e *broker.Envelope) {
	if len(e.Attributes) == 0 {
		return
	}

	for k := range e.Attributes {
		lk := strings.ToLower(k)
		for _, f := range forbiddenAttrKeys {
			if strings.Contains(lk, f) {
				delete(e.Attributes, k)

				break
			}
		}
	}

	for k, v := range e.Attributes {
		if s, ok := v.(string); ok {
			if rs := []rune(s); len(rs) > maxAttrValueLen {
				e.Attributes[k] = string(rs[:maxAttrValueLen])
			}
		}
	}
}

// LegalHold is the POST /v1/legal-holds body.
type LegalHold struct {
	Subject string `json:"subject" validate:"required"`
	Reason  string `json:"reason"  validate:"omitempty,max=256"`
}

// Validate implements azugo.Validator.
func (r *LegalHold) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}
