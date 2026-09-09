package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/oui"
)

const (
	enrichWorkers      = 4
	enrichQueueMax     = 512
	enrichJobBudget    = 5 * time.Second
	enrichAdmitPerPass = 32
	enrichBands        = 3
)

// enrichJob is one device's pending fingerprint refresh.
type enrichJob struct {
	DeviceID string
	IP       string
	MAC      string
	Reason   EnrichReason
	Queued   time.Time
}

// enrichQueue is a deduplicating priority queue of pending fingerprint work.
//
// A device appears at most once: re-pushing it with a higher-priority reason
// upgrades the pending job in place instead of adding a second one. Jobs are
// served in three bands (manual, then new/woke/unnamed, then stale) so a burst
// of TTL expiries can never delay the device a user just asked about.
type enrichQueue struct {
	mu       sync.Mutex
	pending  map[string]enrichJob  // DeviceID -> job
	bands    [enrichBands][]string // FIFO of DeviceIDs per band
	inflight map[string]bool
	wake     chan struct{} // cap 1; a lossy nudge, not a handoff
}

func newEnrichQueue() *enrichQueue {
	return &enrichQueue{
		pending:  make(map[string]enrichJob),
		inflight: make(map[string]bool),
		wake:     make(chan struct{}, 1),
	}
}

// push enqueues job, or upgrades an already-pending job for the same device to
// a higher-priority band. Returns false when the device is already in flight,
// is already pending at an equal-or-better priority, or the queue is full.
func (q *enrichQueue) push(job enrichJob) bool {
	if job.DeviceID == "" {
		return false
	}
	if job.Queued.IsZero() {
		job.Queued = time.Now()
	}
	band := job.Reason.priority()
	if band < 0 || band >= enrichBands {
		band = enrichBands - 1
	}

	q.mu.Lock()
	if q.inflight[job.DeviceID] {
		q.mu.Unlock()
		return false
	}
	if existing, ok := q.pending[job.DeviceID]; ok {
		if existing.Reason.priority() <= band {
			q.mu.Unlock()
			return false // already queued at least this urgently
		}
		q.removeFromBandLocked(existing.Reason.priority(), job.DeviceID)
		q.pending[job.DeviceID] = job
		q.bands[band] = append(q.bands[band], job.DeviceID)
		q.mu.Unlock()
		q.nudge()
		return true
	}
	if len(q.pending) >= enrichQueueMax && !q.evictForLocked(band) {
		q.mu.Unlock()
		return false
	}
	q.pending[job.DeviceID] = job
	q.bands[band] = append(q.bands[band], job.DeviceID)
	q.mu.Unlock()
	q.nudge()
	return true
}

// evictForLocked frees a slot for a job in band by dropping the newest job from
// the lowest-priority non-empty band below it. Stale work is what to lose.
func (q *enrichQueue) evictForLocked(band int) bool {
	for b := enrichBands - 1; b > band; b-- {
		if n := len(q.bands[b]); n > 0 {
			victim := q.bands[b][n-1]
			q.bands[b] = q.bands[b][:n-1]
			delete(q.pending, victim)
			return true
		}
	}
	return false
}

func (q *enrichQueue) removeFromBandLocked(band int, id string) {
	if band < 0 || band >= enrichBands {
		return
	}
	for i, cur := range q.bands[band] {
		if cur == id {
			q.bands[band] = append(q.bands[band][:i], q.bands[band][i+1:]...)
			return
		}
	}
}

// pop returns the highest-priority pending job and marks it in flight.
func (q *enrichQueue) pop() (enrichJob, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for b := 0; b < enrichBands; b++ {
		for len(q.bands[b]) > 0 {
			id := q.bands[b][0]
			q.bands[b] = q.bands[b][1:]
			job, ok := q.pending[id]
			if !ok {
				continue // evicted while queued
			}
			delete(q.pending, id)
			q.inflight[id] = true
			return job, true
		}
	}
	return enrichJob{}, false
}

// done clears the in-flight marker for a device.
func (q *enrichQueue) done(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inflight, id)
}

// rekey follows a device through the ID migration in upsertDevice, so a queued
// job is not orphaned when a device is remounted under a new scoped ID.
func (q *enrichQueue) rekey(oldID, newID string) {
	if oldID == "" || newID == "" || oldID == newID {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.inflight[oldID] {
		delete(q.inflight, oldID)
		q.inflight[newID] = true
	}
	job, ok := q.pending[oldID]
	if !ok {
		return
	}
	band := job.Reason.priority()
	q.removeFromBandLocked(band, oldID)
	delete(q.pending, oldID)

	if _, clash := q.pending[newID]; clash {
		return // the destination already has work queued
	}
	job.DeviceID = newID
	q.pending[newID] = job
	q.bands[band] = append(q.bands[band], newID)
}

// stats reports queue depth for /api/devices and tests.
func (q *enrichQueue) stats() (pending, inflight int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending), len(q.inflight)
}

// nudge wakes one idle worker. The channel has capacity 1 and the send is
// non-blocking, so a nudge can be lost; workers re-poll to cover that.
func (q *enrichQueue) nudge() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// runEnrichWorkers starts the Tier-3 pool. Workers block on the queue and exit
// when ctx is cancelled. They are never gated on the presence or discovery
// tiers — that independence is the point of the split.
func (e *Engine) runEnrichWorkers(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	for i := 0; i < enrichWorkers; i++ {
		go e.enrichWorker(ctx)
	}
}

func (e *Engine) enrichWorker(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		job, ok := e.enrichQ.pop()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-e.enrichQ.wake:
			case <-time.After(2 * time.Second):
				// wake is lossy by design; re-poll so liveness never depends
				// on a perfect wakeup protocol.
			}
			continue
		}
		func() {
			defer e.enrichQ.done(job.DeviceID)
			if _, err := e.enrichOnce(ctx, job); err != nil {
				slog.Debug("enrichment failed", "id", job.DeviceID,
					"reason", job.Reason, "error", err)
			}
		}()
	}
}

// resolveDetails fingerprints one host, through the test seam when set.
func (e *Engine) resolveDetails(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails {
	e.mu.RLock()
	fn := e.resolveFn
	r := e.mdnsResolver
	e.mu.RUnlock()
	if fn != nil {
		return fn(ctx, in)
	}
	if r == nil {
		return mdns.DeviceDetails{}
	}
	return r.ResolveDeviceCtx(ctx, in)
}

// lookupVendor resolves a MAC vendor, through the test seam when set. This is
// the only path allowed to fall back to the maclookup.app HTTP request.
func (e *Engine) lookupVendor(mac string) string {
	e.mu.RLock()
	fn := e.vendorFn
	e.mu.RUnlock()
	if fn != nil {
		return fn(mac)
	}
	return oui.LookupVendor(mac)
}

// enrichOnce fingerprints one device. The vendor lookup and the mDNS/DNS/NetBIOS
// fan-out run concurrently; results are merged under e.mu and emitted after.
func (e *Engine) enrichOnce(ctx context.Context, job enrichJob) (changed bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dev, ok := e.GetDevice(job.DeviceID)
	if !ok {
		// The device may have been remounted under a new ID between queueing
		// and now; fall back to identity.
		e.mu.RLock()
		if d := e.findKnownForPresenceLocked(job.IP, job.MAC); d != nil {
			dev, ok = *d, true
		}
		e.mu.RUnlock()
		if !ok {
			return false, fmt.Errorf("device not found")
		}
		job.DeviceID = dev.ID
	}
	if dev.IP == "" {
		e.markEnriched(job.DeviceID, time.Now(), false)
		return false, nil
	}

	// Probing a device the presence tier says is down is pure waste. Recording
	// it as a failure lets the backoff retire a permanently-absent DHCP row
	// instead of retrying it at the unnamed TTL forever.
	if !dev.IsOnline && job.Reason != EnrichReasonManual && job.Reason != EnrichReasonNew {
		e.markEnriched(job.DeviceID, time.Now(), false)
		return false, nil
	}

	jctx, cancel := context.WithTimeout(ctx, enrichJobBudget)
	defer cancel()

	netKey, gatewayIP, hostIP, hostMAC, hostName := e.netIdentity()
	isGateway := dev.IP != "" && dev.IP == gatewayIP
	isHost := (hostIP != "" && dev.IP == hostIP) ||
		(hostMAC != "" && dev.MAC != "" && NormalizeMAC(dev.MAC) == NormalizeMAC(hostMAC))
	_ = netKey

	var (
		wg      sync.WaitGroup
		vendor  string
		details mdns.DeviceDetails
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		vendor = e.lookupVendor(dev.MAC)
	}()
	go func() {
		defer wg.Done()
		in := mdns.ResolveInput{
			IP:          dev.IP,
			MAC:         dev.MAC,
			Vendor:      dev.Vendor,
			IsGateway:   isGateway,
			ARPHostname: dev.Hostname,
		}
		if isHost {
			in.HostComputerName = hostName
		}
		details = e.resolveDetails(jctx, in)
	}()
	wg.Wait()

	now := time.Now()
	e.mu.Lock()
	d, ok := e.devices[job.DeviceID]
	if !ok {
		e.mu.Unlock()
		return false, fmt.Errorf("device disappeared during enrichment")
	}
	before := *d
	changed = applyDetailsLocked(d, details, vendor)
	d.LastEnrichedAt = now
	d.EnrichFailures = 0
	out := *d
	e.mu.Unlock()

	// Persist even when only the bookkeeping moved, so the TTL survives a restart.
	e.persistDevice(out)
	if deviceChangedMeaningfully(before, out) {
		e.emitEvent("device_updated", &out)
	}
	return changed, nil
}

// markEnriched stamps the enrichment timestamp without a fingerprint, counting
// a failure when the attempt yielded nothing.
func (e *Engine) markEnriched(id string, at time.Time, success bool) {
	e.mu.Lock()
	d, ok := e.devices[id]
	if !ok {
		e.mu.Unlock()
		return
	}
	d.LastEnrichedAt = at
	if success {
		d.EnrichFailures = 0
	} else {
		d.EnrichFailures++
	}
	out := *d
	e.mu.Unlock()
	e.persistDevice(out)
}

// netIdentity snapshots the fields of the active network that fingerprinting needs.
func (e *Engine) netIdentity() (netKey, gatewayIP, hostIP, hostMAC, hostName string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	netKey = e.activeNetworkKey
	if e.netInfo != nil {
		gatewayIP = e.netInfo.GatewayIP
		hostIP = e.netInfo.IP
		hostMAC = e.netInfo.MAC
		hostName = e.netInfo.ComputerName
	}
	return netKey, gatewayIP, hostIP, hostMAC, hostName
}

// RequestEnrichment queues a fingerprint refresh for a device. queued=false
// means a job for it is already pending or in flight, which is not an error —
// the same contract as TryStartPortScan.
func (e *Engine) RequestEnrichment(id string, reason EnrichReason) (queued bool, err error) {
	dev, ok := e.GetDevice(id)
	if !ok {
		return false, fmt.Errorf("device not found")
	}
	if reason == "" {
		reason = EnrichReasonManual
	}
	return e.enrichQ.push(enrichJob{
		DeviceID: dev.ID,
		IP:       dev.IP,
		MAC:      dev.MAC,
		Reason:   reason,
		Queued:   time.Now(),
	}), nil
}

// enqueueIfStale queues d when needsEnrichment says it is due. Cheap enough to
// call for every device on every tier pass.
func (e *Engine) enqueueIfStale(d Device, now time.Time) bool {
	reason, due := needsEnrichment(d, now, e.enrichTTL())
	if !due {
		return false
	}
	return e.enrichQ.push(enrichJob{
		DeviceID: d.ID,
		IP:       d.IP,
		MAC:      d.MAC,
		Reason:   reason,
		Queued:   now,
	})
}

// enqueueWoke queues a device that just came back online, so a sleeping device
// gets named the moment it wakes.
func (e *Engine) enqueueWoke(d Device) bool {
	if d.Hostname != "" && d.CustomName != "" && d.DeviceType != "" {
		return false // nothing left to learn
	}
	return e.enrichQ.push(enrichJob{
		DeviceID: d.ID,
		IP:       d.IP,
		MAC:      d.MAC,
		Reason:   EnrichReasonWoke,
		Queued:   time.Now(),
	})
}

// EnrichStats reports Tier-3 queue depth.
type EnrichStats struct {
	Pending  int `json:"enrich_pending"`
	Inflight int `json:"enrich_inflight"`
}

// EnrichmentStats returns the current queue depth.
func (e *Engine) EnrichmentStats() EnrichStats {
	pending, inflight := e.enrichQ.stats()
	return EnrichStats{Pending: pending, Inflight: inflight}
}
