// Copyright 2026 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package opensandbox

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// SandboxPool is the interface for a client-side sandbox pool.
type SandboxPool interface {
	Start(ctx context.Context) error
	Acquire(ctx context.Context, opts AcquireOptions) (*Sandbox, error)
	ReleaseAllIdle(ctx context.Context) (int, error)
	Resize(ctx context.Context, newMaxIdle int) error
	Snapshot(ctx context.Context) (*PoolSnapshot, error)
	SnapshotIdleEntries(ctx context.Context) ([]IdleEntry, error)
	Shutdown(ctx context.Context, graceful bool) error
}

var _ SandboxPool = (*DefaultSandboxPool)(nil)

// DefaultSandboxPool implements SandboxPool.
type DefaultSandboxPool struct {
	config     *PoolConfig
	stateStore PoolStateStore
	manager    *SandboxManager

	mu             sync.Mutex
	lifecycleState PoolLifecycleState
	healthState    PoolHealthState

	reconciler   *reconcileState
	ticker       *time.Ticker
	done         chan struct{}
	doneClosed   bool
	wg           sync.WaitGroup
	shutdownDone chan struct{} // closed when Shutdown fully completes
	inFlight     int32
	reconCancel  context.CancelFunc
}

// Start begins the background reconciliation loop.
func (p *DefaultSandboxPool) Start(ctx context.Context) error {
	p.mu.Lock()

	if p.lifecycleState == PoolLifecycleRunning || p.lifecycleState == PoolLifecycleStarting {
		p.mu.Unlock()
		return nil
	}

	if p.lifecycleState == PoolLifecycleDraining {
		p.mu.Unlock()
		return nil
	}

	// If restarting from STOPPED, wait for the previous shutdown to fully
	// complete before creating new goroutines on the same WaitGroup.
	if p.lifecycleState == PoolLifecycleStopped && p.shutdownDone != nil {
		ch := p.shutdownDone
		p.mu.Unlock()
		<-ch
		p.mu.Lock()
		// Re-check after re-acquiring lock — another goroutine may have started.
		if p.lifecycleState == PoolLifecycleRunning || p.lifecycleState == PoolLifecycleStarting {
			p.mu.Unlock()
			return nil
		}
	}

	p.lifecycleState = PoolLifecycleStarting
	if p.config.PrimaryLockTTL <= p.config.WarmupReadyTimeout {
		p.config.Logger.Warn("pool primary lock TTL may expire during warmup; "+
			"configure PrimaryLockTTL greater than WarmupReadyTimeout plus expected preparer time",
			"pool_name", p.config.PoolName,
			"primary_lock_ttl", p.config.PrimaryLockTTL,
			"warmup_ready_timeout", p.config.WarmupReadyTimeout)
	}
	p.reconciler = newReconcileState(p.config.DegradedThreshold)
	p.ticker = time.NewTicker(p.config.ReconcileInterval)
	p.done = make(chan struct{})
	p.doneClosed = false
	p.shutdownDone = make(chan struct{})

	reconCtx, reconCancel := context.WithCancel(context.Background())
	p.reconCancel = reconCancel

	p.wg.Add(1)
	go p.reconcileLoop(reconCtx)

	// Trigger immediate first tick if maxIdle > 0.
	if p.config.MaxIdle > 0 {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.runReconcileTick(reconCtx)
			p.syncHealthState()
		}()
	}

	p.lifecycleState = PoolLifecycleRunning
	p.mu.Unlock()

	p.config.Logger.Info("pool started",
		"pool_name", p.config.PoolName,
		"max_idle", p.config.MaxIdle)
	return nil
}

func (p *DefaultSandboxPool) reconcileLoop(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-p.done:
			return
		case <-p.ticker.C:
			if p.reconciler.shouldBackoff() {
				continue
			}
			// Do not use ReconcileInterval as context timeout — the interval
			// controls how often ticks fire, not how long each tick may run.
			// Sandbox creation has its own timeouts (WarmupReadyTimeout).
			p.runReconcileTick(ctx)
			p.syncHealthState()
		}
	}
}

func (p *DefaultSandboxPool) syncHealthState() {
	p.mu.Lock()
	hs, _, _, _ := p.reconciler.snapshot()
	p.healthState = hs
	p.mu.Unlock()
}

func (p *DefaultSandboxPool) runReconcileTick(ctx context.Context) {
	createFn := func(ctx context.Context, reason PooledSandboxCreateReason) (string, error) {
		return p.createOneSandbox(ctx, reason)
	}
	deleteFn := func(sandboxID string) {
		p.killSandboxBestEffort(sandboxID)
	}
	reconcileTick(ctx, p.config, p.stateStore, p.reconciler, p.config.Logger, createFn, deleteFn)
}

// Acquire takes or creates a sandbox from the pool.
func (p *DefaultSandboxPool) Acquire(ctx context.Context, opts AcquireOptions) (*Sandbox, error) {
	// Lifecycle guard.
	p.mu.Lock()
	state := p.lifecycleState
	p.mu.Unlock()
	if state != PoolLifecycleRunning {
		return nil, &PoolNotRunningError{PoolName: p.config.PoolName, State: state}
	}

	// Track in-flight operation.
	atomic.AddInt32(&p.inFlight, 1)
	defer atomic.AddInt32(&p.inFlight, -1)

	// Re-check after incrementing (race with shutdown).
	p.mu.Lock()
	state = p.lifecycleState
	p.mu.Unlock()
	if state != PoolLifecycleRunning {
		return nil, &PoolNotRunningError{PoolName: p.config.PoolName, State: state}
	}

	// Resolve policy.
	policy := p.config.EmptyBehavior
	if opts.Policy != nil {
		policy = *opts.Policy
	}

	// Resolve minTTL.
	minTTL := p.config.AcquireMinRemainingTTL
	if opts.MinRemainingTTL > 0 {
		minTTL = opts.MinRemainingTTL
	}

	// Try take from idle.
	var takeResult *TakeIdleResult
	var err error
	if minTTL > 0 {
		takeResult, err = p.stateStore.TryTakeIdleWithMinTTL(ctx, p.config.PoolName, minTTL)
	} else {
		sandboxID, takeErr := p.stateStore.TryTakeIdle(ctx, p.config.PoolName)
		if takeErr != nil {
			err = takeErr
		} else {
			takeResult = &TakeIdleResult{SandboxID: sandboxID}
		}
	}
	if err != nil {
		// Under FailFast, propagate the store error immediately.
		if policy == AcquirePolicyFailFast {
			return nil, &PoolStateStoreUnavailableError{Operation: "TryTakeIdle", Cause: err}
		}
		// Under DirectCreate, treat store unavailability as a cache miss and
		// fall through to direct create so the pool remains at least as available
		// as raw SDK usage during store outages (OSEP-0005 error-code matrix).
		p.config.Logger.Warn("acquire: state store unavailable, falling through to direct create",
			"pool_name", p.config.PoolName,
			"error", err)
	}

	var idleConnectErr error
	if takeResult != nil && takeResult.SandboxID != "" {
		// Try to connect to the idle sandbox.
		sb, connectErr := p.connectAndRenew(ctx, takeResult.SandboxID, opts)
		if connectErr == nil {
			// Success - do health check if configured.
			if !opts.SkipHealthCheck && p.config.AcquireHealthCheck != nil {
				hcCtx, hcCancel := context.WithTimeout(ctx, p.config.AcquireReadyTimeout)
				hcErr := p.config.AcquireHealthCheck(hcCtx, sb)
				hcCancel()
				if hcErr != nil {
					// Health check failed.
					_ = p.stateStore.RemoveIdle(ctx, p.config.PoolName, takeResult.SandboxID)
					go p.killSandboxBestEffort(takeResult.SandboxID)
					go p.killDiscardedAliveSandboxes(takeResult.DiscardedAliveSandboxIDs)
					if policy == AcquirePolicyFailFast {
						return nil, &PoolAcquireFailedError{PoolName: p.config.PoolName, Cause: hcErr}
					}
					idleConnectErr = hcErr
					p.config.Logger.Warn("acquire: idle health check failed, falling through to direct create",
						"pool_name", p.config.PoolName,
						"sandbox_id", takeResult.SandboxID,
						"error", hcErr)
					goto directCreate
				}
			}
			go p.killDiscardedAliveSandboxes(takeResult.DiscardedAliveSandboxIDs)
			p.config.Logger.Debug("acquire: from idle",
				"pool_name", p.config.PoolName,
				"sandbox_id", takeResult.SandboxID)
			return sb, nil
		}

		idleConnectErr = connectErr
		_ = p.stateStore.RemoveIdle(ctx, p.config.PoolName, takeResult.SandboxID)
		go p.killSandboxBestEffort(takeResult.SandboxID)
		p.config.Logger.Warn("acquire: idle sandbox connect failed",
			"pool_name", p.config.PoolName,
			"sandbox_id", takeResult.SandboxID,
			"error", connectErr)
	}

	// Schedule kill of discarded-alive (whether we got a sandbox ID or not).
	if takeResult != nil {
		go p.killDiscardedAliveSandboxes(takeResult.DiscardedAliveSandboxIDs)
	}

directCreate:
	if policy == AcquirePolicyFailFast {
		if idleConnectErr != nil {
			return nil, &PoolAcquireFailedError{PoolName: p.config.PoolName, Cause: idleConnectErr}
		}
		return nil, &PoolEmptyError{PoolName: p.config.PoolName, Policy: policy}
	}

	// DIRECT_CREATE path.
	return p.directCreate(ctx, opts)
}

func (p *DefaultSandboxPool) connectAndRenew(ctx context.Context, sandboxID string, opts AcquireOptions) (*Sandbox, error) {
	var readyOpts ReadyOptions
	if !opts.SkipHealthCheck {
		readyOpts = ReadyOptions{
			Timeout:         p.config.AcquireReadyTimeout,
			PollingInterval: p.config.AcquireHealthCheckPollingInterval,
		}
	}
	sb, err := ConnectSandbox(ctx, p.config.ConnectionConfig, sandboxID, readyOpts)
	if err != nil {
		return nil, err
	}
	if opts.SandboxTimeout > 0 {
		if _, err := sb.Renew(ctx, opts.SandboxTimeout); err != nil {
			return nil, fmt.Errorf("opensandbox: pool acquire: renew after connect failed: %w", err)
		}
	}
	return sb, nil
}

func (p *DefaultSandboxPool) directCreate(ctx context.Context, opts AcquireOptions) (*Sandbox, error) {
	if p.config.SandboxCreator != nil {
		createCtx := PooledSandboxCreateContext{
			PoolName:         p.config.PoolName,
			OwnerID:          p.config.OwnerID,
			IdleTimeout:      p.config.IdleTimeout,
			Reason:           CreateReasonAcquire,
			ReadyTimeout:     p.config.AcquireReadyTimeout,
			SkipHealthCheck:  opts.SkipHealthCheck,
			ConnectionConfig: p.config.ConnectionConfig,
			CreationSpec:     p.config.CreationSpec,
		}
		sb, err := p.config.SandboxCreator.Create(ctx, createCtx)
		if err != nil {
			return nil, err
		}
		if opts.SandboxTimeout > 0 {
			if _, err := sb.Renew(ctx, opts.SandboxTimeout); err != nil {
				go p.killSandboxBestEffort(sb.ID())
				_ = sb.Close()
				return nil, fmt.Errorf("opensandbox: pool direct create: renew failed: %w", err)
			}
		}
		// Run acquire health check on direct-created sandbox.
		if !opts.SkipHealthCheck && p.config.AcquireHealthCheck != nil {
			hcCtx, hcCancel := context.WithTimeout(ctx, p.config.AcquireReadyTimeout)
			hcErr := p.config.AcquireHealthCheck(hcCtx, sb)
			hcCancel()
			if hcErr != nil {
				go p.killSandboxBestEffort(sb.ID())
				_ = sb.Close()
				return nil, fmt.Errorf("opensandbox: pool direct create: health check failed: %w", hcErr)
			}
		}
		return sb, nil
	}

	sb, err := p.createSandboxFromSpec(ctx, p.config.AcquireReadyTimeout, opts.SkipHealthCheck)
	if err != nil {
		return nil, err
	}
	if opts.SandboxTimeout > 0 {
		if _, err := sb.Renew(ctx, opts.SandboxTimeout); err != nil {
			go p.killSandboxBestEffort(sb.ID())
			_ = sb.Close()
			return nil, fmt.Errorf("opensandbox: pool direct create: renew failed: %w", err)
		}
	}
	// Run acquire health check on direct-created sandbox.
	if !opts.SkipHealthCheck && p.config.AcquireHealthCheck != nil {
		hcCtx, hcCancel := context.WithTimeout(ctx, p.config.AcquireReadyTimeout)
		hcErr := p.config.AcquireHealthCheck(hcCtx, sb)
		hcCancel()
		if hcErr != nil {
			go p.killSandboxBestEffort(sb.ID())
			_ = sb.Close()
			return nil, fmt.Errorf("opensandbox: pool direct create: health check failed: %w", hcErr)
		}
	}
	return sb, nil
}

func (p *DefaultSandboxPool) createOneSandbox(ctx context.Context, reason PooledSandboxCreateReason) (string, error) {
	if p.config.SandboxCreator != nil {
		createCtx := PooledSandboxCreateContext{
			PoolName:         p.config.PoolName,
			OwnerID:          p.config.OwnerID,
			IdleTimeout:      p.config.IdleTimeout,
			Reason:           reason,
			ReadyTimeout:     p.config.WarmupReadyTimeout,
			SkipHealthCheck:  p.config.WarmupSkipHealthCheck,
			ConnectionConfig: p.config.ConnectionConfig,
			CreationSpec:     p.config.CreationSpec,
		}
		sb, err := p.config.SandboxCreator.Create(ctx, createCtx)
		if err != nil {
			return "", err
		}
		defer sb.Close()
		sandboxID := sb.ID()
		if err := p.applyWarmupCallbacks(ctx, sb); err != nil {
			go p.killSandboxBestEffort(sandboxID)
			return "", err
		}
		if _, err := sb.Renew(ctx, p.config.IdleTimeout); err != nil {
			p.config.Logger.Warn("pool warmup: renew idle TTL failed",
				"pool_name", p.config.PoolName,
				"sandbox_id", sandboxID,
				"error", err)
		}
		return sandboxID, nil
	}

	sb, err := p.createSandboxFromSpec(ctx, p.config.WarmupReadyTimeout, p.config.WarmupSkipHealthCheck)
	if err != nil {
		return "", err
	}
	defer sb.Close()
	sandboxID := sb.ID()
	if err := p.applyWarmupCallbacks(ctx, sb); err != nil {
		go p.killSandboxBestEffort(sandboxID)
		return "", err
	}
	if _, err := sb.Renew(ctx, p.config.IdleTimeout); err != nil {
		p.config.Logger.Warn("pool warmup: renew idle TTL failed",
			"pool_name", p.config.PoolName,
			"sandbox_id", sandboxID,
			"error", err)
	}
	return sandboxID, nil
}

func (p *DefaultSandboxPool) createSandboxFromSpec(ctx context.Context, readyTimeout time.Duration, skipHealthCheck bool) (*Sandbox, error) {
	spec := p.config.CreationSpec
	timeoutSec := int(p.config.IdleTimeout.Seconds())
	createOpts := SandboxCreateOptions{
		Image:           spec.Image,
		SnapshotID:      spec.SnapshotID,
		Entrypoint:      spec.Entrypoint,
		ResourceLimits:  spec.ResourceLimits,
		TimeoutSeconds:  &timeoutSec,
		Env:             spec.Env,
		Metadata:        spec.Metadata,
		NetworkPolicy:   spec.NetworkPolicy,
		Volumes:         spec.Volumes,
		Extensions:      spec.Extensions,
		Platform:        spec.Platform,
		ManualCleanup:   spec.ManualCleanup,
		SecureAccess:    spec.SecureAccess,
		CredentialProxy: spec.CredentialProxy,
		SkipHealthCheck: skipHealthCheck,
		ReadyTimeout:    readyTimeout,
	}
	return CreateSandbox(ctx, p.config.ConnectionConfig, createOpts)
}

func (p *DefaultSandboxPool) applyWarmupCallbacks(ctx context.Context, sb *Sandbox) error {
	if p.config.WarmupHealthCheck != nil && !p.config.WarmupSkipHealthCheck {
		hcCtx, hcCancel := context.WithTimeout(ctx, p.config.WarmupReadyTimeout)
		err := p.config.WarmupHealthCheck(hcCtx, sb)
		hcCancel()
		if err != nil {
			return err
		}
	}
	if p.config.WarmupSandboxPreparer != nil {
		if err := p.config.WarmupSandboxPreparer(ctx, sb); err != nil {
			return err
		}
	}
	return nil
}

// ReleaseAllIdle drains all idle sandboxes and kills them.
func (p *DefaultSandboxPool) ReleaseAllIdle(ctx context.Context) (int, error) {
	count := 0
	for {
		sandboxID, err := p.stateStore.TryTakeIdle(ctx, p.config.PoolName)
		if err != nil {
			return count, err
		}
		if sandboxID == "" {
			break
		}
		p.killSandboxBestEffort(sandboxID)
		count++
	}
	return count, nil
}

// Resize dynamically changes the idle target.
func (p *DefaultSandboxPool) Resize(ctx context.Context, newMaxIdle int) error {
	if newMaxIdle < 0 {
		return fmt.Errorf("opensandbox: pool resize: maxIdle must be >= 0, got %d", newMaxIdle)
	}
	if err := p.stateStore.SetMaxIdle(ctx, p.config.PoolName, newMaxIdle); err != nil {
		return err
	}
	p.mu.Lock()
	p.config.MaxIdle = newMaxIdle
	p.mu.Unlock()
	return nil
}

// Snapshot returns a point-in-time snapshot of pool state.
func (p *DefaultSandboxPool) Snapshot(ctx context.Context) (*PoolSnapshot, error) {
	p.mu.Lock()
	ls := p.lifecycleState
	hs := p.healthState
	p.mu.Unlock()

	counters, err := p.stateStore.SnapshotCounters(ctx, p.config.PoolName)
	if err != nil {
		return nil, err
	}

	maxIdle, err := p.stateStore.GetMaxIdle(ctx, p.config.PoolName)
	if err != nil {
		return nil, err
	}

	var failureCount int
	var backoffActive bool
	var lastError string
	if p.reconciler != nil {
		_, failureCount, backoffActive, lastError = p.reconciler.snapshot()
	}

	return &PoolSnapshot{
		LifecycleState:     ls,
		HealthState:        hs,
		IdleCount:          counters.IdleCount,
		MaxIdle:            maxIdle,
		FailureCount:       failureCount,
		BackoffActive:      backoffActive,
		LastError:          lastError,
		InFlightOperations: int(atomic.LoadInt32(&p.inFlight)),
	}, nil
}

// SnapshotIdleEntries returns the current idle entries.
func (p *DefaultSandboxPool) SnapshotIdleEntries(ctx context.Context) ([]IdleEntry, error) {
	return p.stateStore.SnapshotIdleEntries(ctx, p.config.PoolName)
}

// Shutdown stops the pool and releases idle sandboxes.
func (p *DefaultSandboxPool) Shutdown(ctx context.Context, graceful bool) error {
	p.mu.Lock()
	if p.lifecycleState == PoolLifecycleStopped {
		p.mu.Unlock()
		return nil
	}
	if p.lifecycleState == PoolLifecycleNotStarted {
		p.lifecycleState = PoolLifecycleStopped
		p.mu.Unlock()
		return nil
	}

	if !graceful {
		p.lifecycleState = PoolLifecycleStopped
		if p.ticker != nil {
			p.ticker.Stop()
		}
		if p.done != nil && !p.doneClosed {
			close(p.done)
			p.doneClosed = true
		}
		if p.reconCancel != nil {
			p.reconCancel()
		}
		sdCh := p.shutdownDone
		p.mu.Unlock()
		p.wg.Wait()
		_ = p.stateStore.ReleasePrimaryLock(ctx, p.config.PoolName, p.config.OwnerID)
		p.config.Logger.Info("pool shutdown (non-graceful)",
			"pool_name", p.config.PoolName)
		if sdCh != nil {
			select {
			case <-sdCh:
			default:
				close(sdCh)
			}
		}
		return nil
	}

	// Graceful shutdown.
	p.lifecycleState = PoolLifecycleDraining
	if p.ticker != nil {
		p.ticker.Stop()
	}
	if p.done != nil && !p.doneClosed {
		close(p.done)
		p.doneClosed = true
	}
	p.mu.Unlock()

	p.wg.Wait()
	_ = p.stateStore.ReleasePrimaryLock(ctx, p.config.PoolName, p.config.OwnerID)

	// Wait for in-flight operations to drain.
	if p.config.DrainTimeout > 0 {
		deadline := time.After(p.config.DrainTimeout)
		for atomic.LoadInt32(&p.inFlight) > 0 {
			select {
			case <-deadline:
				goto done
			case <-time.After(100 * time.Millisecond):
			}
		}
	}

done:
	p.mu.Lock()
	p.lifecycleState = PoolLifecycleStopped
	sdCh := p.shutdownDone
	p.mu.Unlock()
	p.config.Logger.Info("pool shutdown (graceful)",
		"pool_name", p.config.PoolName)
	if sdCh != nil {
		select {
		case <-sdCh:
		default:
			close(sdCh)
		}
	}
	return nil
}

func (p *DefaultSandboxPool) killSandboxBestEffort(sandboxID string) {
	_ = p.manager.KillSandbox(context.Background(), sandboxID)
}

func (p *DefaultSandboxPool) killDiscardedAliveSandboxes(ids []string) {
	for _, id := range ids {
		p.killSandboxBestEffort(id)
	}
}
