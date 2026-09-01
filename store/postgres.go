package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// Postgres is the platform store: the append-only, subject-indexed access log in
// the `access_audit` schema, reached ONLY through SECURITY DEFINER procedures
// under the EXECUTE-only `access_audit_public` role (authbyte-db/
// access-audit). This package never issues raw table SQL — it only CALLs the
// procedures (mirrors authbyte/store and trust-anchor/store).
//
// Selected when ACCESS_AUDIT_STORE_DSN is set; the in-memory backend is the
// development/test default.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a connection pool to the platform PostgreSQL. The pool is
// lazy; connectivity is verified on first use (or via Ping).
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: postgres connect: %w", err)
	}

	return &Postgres{pool: pool}, nil
}

// Close releases the connection pool.
func (p *Postgres) Close() { p.pool.Close() }

// Ping verifies backend connectivity.
func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// envelope is the structured result every procedure returns
// (util.result_success / util.result_error).
type envelope struct {
	Result  string          `json:"result"`
	Data    json.RawMessage `json:"data"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
}

// call invokes a SECURITY DEFINER procedure with the uniform JSONB envelope and
// returns the decoded `data` payload, or a typed error from result_error.
func (p *Postgres) call(ctx context.Context, proc string, in any) (json.RawMessage, error) {
	inJSON, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("store: marshal input: %w", err)
	}

	// CALL with an INOUT parameter returns a single-column row carrying po_data;
	// NULL seeds the INOUT slot.
	q := fmt.Sprintf("CALL %s($1::jsonb, NULL::jsonb)", proc)

	var out []byte
	if err := p.pool.QueryRow(ctx, q, inJSON).Scan(&out); err != nil {
		// A procedure that fails after a write re-raises a structured error with
		// SQLSTATE P0001 (Pattern B) to force a rollback; its message is the
		// util.result_error JSON. Recover the code/message so callers see the
		// same shape as the validation (returned-error) path.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "P0001" {
			var env envelope
			if json.Unmarshal([]byte(pgErr.Message), &env) == nil && env.Result == "error" {
				return nil, fmt.Errorf("store: %s: %s: %s", proc, env.Code, env.Message)
			}
		}

		return nil, fmt.Errorf("store: %s: %w", proc, err)
	}

	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, fmt.Errorf("store: %s: decode result: %w", proc, err)
	}
	if env.Result != "success" {
		return nil, fmt.Errorf("store: %s: %s: %s", proc, env.Code, env.Message)
	}

	return env.Data, nil
}

type appendInput struct {
	Record        *broker.Envelope `json:"record"`
	Seal          string           `json:"seal"`
	SourceService string           `json:"source_service,omitempty"`
	System        string           `json:"system,omitempty"`
}

// Append appends rec via access_audit.append_record (idempotent on event id).
func (p *Postgres) Append(ctx context.Context, rec *Record) (*AppendResult, error) {
	env := rec.Envelope
	data, err := p.call(ctx, "access_audit.append_record", appendInput{
		Record:        &env,
		Seal:          rec.Seal,
		SourceService: rec.SourceService,
		System:        rec.System,
	})
	if err != nil {
		return nil, err
	}

	var res struct {
		RecordID  string `json:"recordId"`
		EventID   string `json:"eventId"`
		Duplicate bool   `json:"duplicate"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: append: decode: %w", err)
	}

	return &AppendResult{RecordID: res.RecordID, EventID: res.EventID, Duplicate: res.Duplicate}, nil
}

// BySubject returns the subject's access records via access_audit.records_by_subject.
func (p *Postgres) BySubject(ctx context.Context, subject string, from, to time.Time, limit int) ([]*Record, error) {
	in := map[string]any{"subject": subject}
	if !from.IsZero() {
		in["from"] = from.UTC().Format(time.RFC3339Nano)
	}
	if !to.IsZero() {
		in["to"] = to.UTC().Format(time.RFC3339Nano)
	}
	if limit > 0 {
		in["limit"] = limit
	}

	data, err := p.call(ctx, "access_audit.records_by_subject", in)
	if err != nil {
		return nil, err
	}

	var res struct {
		Records []struct {
			Content json.RawMessage `json:"content"`
			Seal    string          `json:"seal"`
			Seq     int64           `json:"seq"`
		} `json:"records"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: by_subject: decode: %w", err)
	}

	out := make([]*Record, 0, len(res.Records))
	for i := range res.Records {
		r := res.Records[i]

		var ev broker.Envelope
		if err := json.Unmarshal(r.Content, &ev); err != nil {
			return nil, fmt.Errorf("store: by_subject: decode record: %w", err)
		}
		out = append(out, &Record{Envelope: ev, Seal: r.Seal, Seq: r.Seq})
	}

	return out, nil
}

// SealsForPeriod returns the period's seals (ordered by event id) and count.
func (p *Postgres) SealsForPeriod(ctx context.Context, period string) ([]string, int, error) {
	data, err := p.call(ctx, "access_audit.seals_for_period", map[string]any{"period": period})
	if err != nil {
		return nil, 0, err
	}

	var res struct {
		Seals []string `json:"seals"`
		Count int      `json:"count"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, 0, fmt.Errorf("store: seals_for_period: decode: %w", err)
	}

	return res.Seals, res.Count, nil
}

// PendingCheckpointPeriods returns periods before `before` lacking a checkpoint.
func (p *Postgres) PendingCheckpointPeriods(ctx context.Context, before string) ([]string, error) {
	data, err := p.call(ctx, "access_audit.periods_pending_checkpoint", map[string]any{"before": before})
	if err != nil {
		return nil, err
	}

	var res struct {
		Periods []string `json:"periods"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: periods_pending_checkpoint: decode: %w", err)
	}

	return res.Periods, nil
}

// SaveCheckpoint persists cp via access_audit.save_checkpoint (write-once).
func (p *Postgres) SaveCheckpoint(ctx context.Context, cp *Checkpoint) (bool, error) {
	data, err := p.call(ctx, "access_audit.save_checkpoint", map[string]any{
		"period":          cp.Period,
		"row_count":       cp.RowCount,
		"checkpoint_seal": cp.Seal,
	})
	if err != nil {
		return false, err
	}

	var res struct {
		Created bool `json:"created"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return false, fmt.Errorf("store: save_checkpoint: decode: %w", err)
	}

	return res.Created, nil
}

// LoadCheckpoint returns the stored checkpoint for period, or (nil, nil).
func (p *Postgres) LoadCheckpoint(ctx context.Context, period string) (*Checkpoint, error) {
	data, err := p.call(ctx, "access_audit.load_checkpoint", map[string]any{"period": period})
	if err != nil {
		return nil, err
	}

	var res struct {
		Checkpoint *struct {
			Period         string    `json:"period"`
			RowCount       int64     `json:"rowCount"`
			CheckpointSeal string    `json:"checkpointSeal"`
			SealedAt       time.Time `json:"sealedAt"`
		} `json:"checkpoint"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: load_checkpoint: decode: %w", err)
	}
	if res.Checkpoint == nil {
		return nil, nil
	}

	return &Checkpoint{
		Period:   res.Checkpoint.Period,
		RowCount: res.Checkpoint.RowCount,
		Seal:     res.Checkpoint.CheckpointSeal,
		SealedAt: res.Checkpoint.SealedAt,
	}, nil
}

// SetLegalHold places or clears a hold via access_audit.set_legal_hold.
func (p *Postgres) SetLegalHold(ctx context.Context, subject, reason, placedBy string, hold bool) error {
	_, err := p.call(ctx, "access_audit.set_legal_hold", map[string]any{
		"subject":   subject,
		"hold":      hold,
		"reason":    reason,
		"placed_by": placedBy,
	})

	return err
}

// PurgeExpired purges periods older than cutoff via access_audit.purge_expired.
func (p *Postgres) PurgeExpired(ctx context.Context, cutoff string) (*PurgeResult, error) {
	data, err := p.call(ctx, "access_audit.purge_expired", map[string]any{"cutoff": cutoff})
	if err != nil {
		return nil, err
	}

	var res struct {
		Cutoff            string `json:"cutoff"`
		Purged            int64  `json:"purged"`
		RetainedUnderHold int64  `json:"retainedUnderHold"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: purge_expired: decode: %w", err)
	}

	return &PurgeResult{Cutoff: res.Cutoff, Purged: res.Purged, RetainedUnderHold: res.RetainedUnderHold}, nil
}
