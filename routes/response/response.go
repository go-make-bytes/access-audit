// Package response holds the access-audit HTTP response DTOs.
package response

import "github.com/gmb-lib/go-platform-kit/broker"

// Recorded is the POST /v1/access-records result.
type Recorded struct {
	RecordID  string `json:"recordId"`
	EventID   string `json:"eventId"`
	Duplicate bool   `json:"duplicate"`
}

// SubjectRecord is one DSAR record: the stored envelope plus the integrity check
// result for its stored seal.
type SubjectRecord struct {
	broker.Envelope

	// Integrity is "ok" when the stored seal verifies, "failed" otherwise.
	Integrity string `json:"integrity"`
}

// SubjectRecords is the GET /v1/subjects/{subject}/access-records result.
type SubjectRecords struct {
	Subject string          `json:"subject"`
	Count   int             `json:"count"`
	Records []SubjectRecord `json:"records"`
}

// Verify is the GET /v1/verify result.
type Verify struct {
	Scope      string   `json:"scope"`   // "subject" | "period"
	Target     string   `json:"target"`  // the subject ref or the period
	Checked    int      `json:"checked"` // records (subject) or rows (period)
	OK         bool     `json:"ok"`
	Mismatches []string `json:"mismatches,omitempty"`
}

// LegalHold is the legal-hold change result.
type LegalHold struct {
	Subject string `json:"subject"`
	Hold    bool   `json:"hold"`
}

// Purge is the manual-purge result.
type Purge struct {
	Cutoff            string `json:"cutoff"`
	Purged            int64  `json:"purged"`
	RetainedUnderHold int64  `json:"retainedUnderHold"`
}
