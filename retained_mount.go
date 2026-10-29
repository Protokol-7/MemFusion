package main

import (
	"context"
	"fmt"
	"memforensics-gui/internal/analyzer"
	"memforensics-gui/internal/memprocfs"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) runRetainedMount(phase context.Context, req RunRequest, emit func(string, any)) {
	// After the analysis returns, mount diagnostics continue to the UI and
	// process debug log, without growing the finalized custody event buffer.
	var detached atomic.Bool
	liveEmit := func(event string, payload any) {
		if detached.Load() {
			runtime.EventsEmit(a.ctx, event, payload)
		} else {
			emit(event, payload)
		}
	}
	defer detached.Store(true)
	a.runRetainedMountWith(phase,
		func(ctx context.Context, ready func()) error {
			return memprocfs.RunForensicScan(ctx, req.MemProcfsPath, req.ImagePath, req.OutputDir, liveEmit, ready)
		},
		func(ctx context.Context) {
			if req.IncludeAnalyzer {
				if err := analyzer.Run(ctx, req.AnalyzerPath, req.MemProcfsPath, req.ImagePath, memprocfs.ActiveMountDir(), req.OutputDir, emit); err != nil {
					emit("run:log", map[string]any{"source": "analyzer", "line": err.Error()})
				}
			}
		}, func() {
			emit("memprocfs:status", map[string]any{"state": "mounted", "message": "Analysis ended. Mount retained at " + memprocfs.ActiveMountDir() + "; open or unmount it from Mounts."})
		}, func() { runtime.EventsEmit(a.ctx, "mounts:changed", nil) })
}

// The process belongs to the app lifetime, not the completed analysis phase.
// While analysis is active, Skip/Stop still cancel both scanner and analyzer.
func (a *App) runRetainedMountWith(phase context.Context, scan func(context.Context, func()) error, analyze func(context.Context), retained, released func()) {
	mountCtx, cancelMount := context.WithCancel(a.ctx)
	done := make(chan struct{})
	ready := make(chan struct{}, 1)
	a.runMu.Lock()
	a.mountCancel, a.mountDone = cancelMount, done
	a.runMu.Unlock()
	analysisCtx, cancelAnalysis := context.WithCancel(phase)
	defer cancelAnalysis()
	stopRelay := context.AfterFunc(phase, cancelMount)
	defer stopRelay()
	go func() {
		defer func() {
			cancelMount()
			cancelAnalysis()
			a.runMu.Lock()
			if a.mountDone == done {
				a.mountCancel, a.mountDone = nil, nil
			}
			close(done)
			a.runMu.Unlock()
			released()
		}()
		_ = scan(mountCtx, func() {
			select {
			case ready <- struct{}{}:
			default:
			}
		})
	}()
	keep := false
	defer func() {
		if !keep {
			cancelMount()
			<-done
		}
	}()
	select {
	case <-phase.Done():
		return
	case <-done:
		return
	case <-ready:
	}
	if analysisCtx.Err() != nil {
		return
	}
	analyze(analysisCtx)
	// Detach before endPhase cancels its context. If cancellation already
	// started, wait for process exit instead of reporting a retained mount.
	if !stopRelay() || phase.Err() != nil || mountCtx.Err() != nil {
		return
	}
	keep = true
	retained()
}

// GetRetainedMountPath returns the completed run's live mount, if any.
func (a *App) GetRetainedMountPath() string {
	a.runMu.Lock()
	defer a.runMu.Unlock()
	if a.running || a.mountDone == nil {
		return ""
	}
	return memprocfs.ActiveMountDir()
}

func (a *App) unmountRetained(path string) (bool, error) {
	a.runMu.Lock()
	if a.mountDone == nil || !sameMount(path, memprocfs.ActiveMountDir()) {
		a.runMu.Unlock()
		return false, nil
	}
	if a.running {
		a.runMu.Unlock()
		return true, fmt.Errorf("analysis is still using this mount; use Stop or wait for completion")
	}
	done := a.mountDone
	a.mountCancel()
	a.runMu.Unlock()
	select {
	case <-done:
		return true, nil
	case <-time.After(15 * time.Second):
		return true, fmt.Errorf("MemProcFS is still shutting down; refresh Mounts shortly")
	}
}

func sameMount(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
