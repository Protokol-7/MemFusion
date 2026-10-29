package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func waitMountTest(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("mount lifecycle did not finish")
	}
}

func TestRetainedMountSurvivesPhaseAndClosesWithApp(t *testing.T) {
	appCtx, closeApp := context.WithCancel(context.Background())
	defer closeApp()
	a := &App{ctx: appCtx}
	phase, endPhase := context.WithCancel(context.Background())
	defer endPhase()
	released := make(chan struct{})
	var mountContext context.Context
	analyzed, retained := false, false
	a.runRetainedMountWith(phase, func(ctx context.Context, ready func()) error {
		mountContext = ctx
		ready()
		<-ctx.Done()
		return ctx.Err()
	}, func(ctx context.Context) { analyzed = ctx.Err() == nil }, func() { retained = true }, func() { close(released) })
	endPhase()
	if !analyzed || !retained || mountContext.Err() != nil {
		t.Fatal("completion cancelled retained mount")
	}
	if err := a.StartRun(RunRequest{}); err == nil {
		t.Fatal("new run accepted with retained mount")
	}
	if _, err := a.InstallTools(); err == nil {
		t.Fatal("update accepted with retained mount")
	}
	closeApp()
	waitMountTest(t, released)
	if a.mountDone != nil || a.mountCancel != nil {
		t.Fatal("mount state not cleared")
	}
}

func TestSkipOrStopCancelsMountDuringAnalysis(t *testing.T) {
	appCtx, closeApp := context.WithCancel(context.Background())
	defer closeApp()
	a := &App{ctx: appCtx}
	phase, stop := context.WithCancel(appCtx)
	defer stop()
	entered := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		a.runRetainedMountWith(phase, func(ctx context.Context, ready func()) error { ready(); <-ctx.Done(); return ctx.Err() },
			func(ctx context.Context) { close(entered); <-ctx.Done() }, func() { t.Error("cancelled mount retained") }, func() {})
	}()
	waitMountTest(t, entered)
	stop()
	waitMountTest(t, finished)
	if a.mountDone != nil {
		t.Fatal("cancelled process left registered")
	}
}

func TestMountExitBeforeScanDoesNotRunAnalyzer(t *testing.T) {
	a := &App{ctx: context.Background()}
	a.runRetainedMountWith(context.Background(), func(context.Context, func()) error { return errors.New("launch failed") },
		func(context.Context) { t.Error("analyzer ran without scan") }, func() { t.Error("dead mount retained") }, func() {})
	if a.mountDone != nil {
		t.Fatal("failed process left registered")
	}
}

func TestExplicitCancellationReleasesRetainedMount(t *testing.T) {
	a := &App{ctx: context.Background()}
	released := make(chan struct{})
	a.runRetainedMountWith(context.Background(), func(ctx context.Context, ready func()) error {
		ready()
		<-ctx.Done()
		return ctx.Err()
	}, func(context.Context) {}, func() {}, func() { close(released) })
	a.runMu.Lock()
	cancel := a.mountCancel
	a.runMu.Unlock()
	cancel()
	waitMountTest(t, released)
	if a.mountDone != nil {
		t.Fatal("explicit unmount did not release process state")
	}
}

func TestMountExitCancelsAnalyzer(t *testing.T) {
	a := &App{ctx: context.Background()}
	exit := make(chan struct{})
	a.runRetainedMountWith(context.Background(), func(ctx context.Context, ready func()) error { ready(); <-exit; return errors.New("process exited") },
		func(ctx context.Context) { close(exit); <-ctx.Done() }, func() { t.Error("dead mount retained") }, func() {})
	if a.mountDone != nil {
		t.Fatal("dead mount left registered")
	}
}
