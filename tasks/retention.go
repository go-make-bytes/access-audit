// Package tasks holds the access-audit background tasks. The retention task is
// the operational half of the integrity + retention design:
// on a schedule it (1) seals a checkpoint for every closed retention period that
// lacks one, then (2) purges records in periods older than the accountability
// window — skipping any subject under legal hold — and reports the purge so the
// fact of deletion is auditable.
package tasks

import (
	"context"
	"time"

	"azugo.io/core"
	"go.uber.org/zap"

	"github.com/go-make-bytes/access-audit/events"
	"github.com/go-make-bytes/access-audit/seal"
	"github.com/go-make-bytes/access-audit/store"
)

// RetentionConfig wires the retention task's dependencies.
type RetentionConfig struct {
	Store    store.Store
	Sealer   *seal.Sealer
	Events   *events.Emitter
	Interval time.Duration
	Window   time.Duration
	// VerifyRetentionDays is the verify abuse-evidence window (days); its sweep
	// rides the same schedule. Zero disables the verify sweep.
	VerifyRetentionDays int
	Logger              *zap.Logger
}

type retentionTask struct {
	cfg    RetentionConfig
	ticker *time.Ticker
	stop   chan bool
}

// NewRetentionTask returns the retention sweep task (checkpoint + purge).
func NewRetentionTask(cfg RetentionConfig) core.Tasker {
	return &retentionTask{cfg: cfg}
}

func (t *retentionTask) Name() string { return "access-audit-retention" }

func (t *retentionTask) Start(ctx context.Context) error {
	t.stop = make(chan bool)
	t.ticker = time.NewTicker(t.cfg.Interval)

	go func() {
		t.runOnce(ctx) // initial sweep on start
		for {
			select {
			case <-t.stop:
				return
			case <-t.ticker.C:
				t.runOnce(ctx)
			}
		}
	}()

	return nil
}

func (t *retentionTask) Stop() {
	if t.ticker != nil {
		t.ticker.Stop()
		t.stop <- true
		t.ticker = nil
	}
}

// runOnce performs one sweep: checkpoint closed periods, then purge expired ones.
func (t *retentionTask) runOnce(ctx context.Context) {
	now := time.Now().UTC()

	// 1. Seal a checkpoint for every closed period (< current month) missing one.
	before := store.Period(now)
	pending, err := t.cfg.Store.PendingCheckpointPeriods(ctx, before)
	if err != nil {
		t.log().Error("retention: list pending checkpoints", zap.Error(err))
	} else {
		for _, p := range pending {
			if err := t.checkpoint(ctx, p); err != nil {
				t.log().Error("retention: checkpoint period", zap.String("period", p), zap.Error(err))
			}
		}
	}

	// 2. Purge periods older than the accountability window (skips legal holds).
	cutoff := store.Period(now.Add(-t.cfg.Window))
	res, err := t.cfg.Store.PurgeExpired(ctx, cutoff)
	if err != nil {
		t.log().Error("retention: purge", zap.String("cutoff", cutoff), zap.Error(err))

		return
	}

	t.cfg.Events.RetentionPurge(res.Cutoff, res.Purged, res.RetainedUnderHold)
	t.log().Info("retention sweep complete",
		zap.String("cutoff", res.Cutoff),
		zap.Int64("purged", res.Purged),
		zap.Int64("retained_under_hold", res.RetainedUnderHold))

	// 3. Sweep the verify abuse-evidence store past its own (shorter) window.
	if t.cfg.VerifyRetentionDays > 0 {
		vres, err := t.cfg.Store.SweepVerifyExpired(ctx, t.cfg.VerifyRetentionDays)
		if err != nil {
			t.log().Error("retention: verify-evidence sweep", zap.Error(err))

			return
		}
		t.log().Info("verify-evidence sweep complete",
			zap.String("cutoff", vres.Cutoff),
			zap.Int64("purged", vres.Purged))
	}
}

func (t *retentionTask) checkpoint(ctx context.Context, period string) error {
	seals, count, err := t.cfg.Store.SealsForPeriod(ctx, period)
	if err != nil {
		return err
	}

	created, err := t.cfg.Store.SaveCheckpoint(ctx, &store.Checkpoint{
		Period:   period,
		RowCount: int64(count),
		Seal:     t.cfg.Sealer.Checkpoint(seals, count),
	})
	if err != nil {
		return err
	}
	if created {
		t.cfg.Events.CheckpointWritten(period, count)
	}

	return nil
}

func (t *retentionTask) log() *zap.Logger {
	if t.cfg.Logger != nil {
		return t.cfg.Logger
	}

	return zap.NewNop()
}
