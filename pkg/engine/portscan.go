package engine

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jaredwarren/Gofing/pkg/ports"
)

// ErrPortScanInProgress is returned when a port scan for the device is already running.
var ErrPortScanInProgress = fmt.Errorf("port scan already in progress")

func (e *Engine) tryBeginPortScan(id string) bool {
	e.portScanMu.Lock()
	defer e.portScanMu.Unlock()
	if e.portScanInflight[id] {
		return false
	}
	e.portScanInflight[id] = true
	return true
}

func (e *Engine) endPortScan(id string) {
	e.portScanMu.Lock()
	defer e.portScanMu.Unlock()
	delete(e.portScanInflight, id)
}

const (
	portScanCommonBudget = 30 * time.Second
	portScanDeepBudget   = 60 * time.Second
)

// TryStartPortScan validates and launches an async port scan. started=false means
// one is already in flight for this device (not an error).
//
// The caller's context is intentionally unused: the scan runs on a detached
// timeout so an HTTP handler returning after scan_started cannot cancel it.
func (e *Engine) TryStartPortScan(_ context.Context, id, mode string) (started bool, err error) {
	if _, ok := e.GetDevice(id); !ok {
		return false, fmt.Errorf("device not found")
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "common"
	}
	if mode != "common" && mode != "deep" {
		return false, fmt.Errorf("invalid mode %q (use common or deep)", mode)
	}
	if !e.tryBeginPortScan(id) {
		return false, nil
	}
	budget := portScanCommonBudget
	if mode == "deep" {
		budget = portScanDeepBudget
	}
	scanCtx, cancel := context.WithTimeout(context.Background(), budget)
	go func() {
		defer cancel()
		defer e.endPortScan(id)
		if _, err := e.runPortScan(scanCtx, id, mode); err != nil {
			slog.Error("port scan failed", "id", id, "mode", mode, "error", err)
			e.emitEvent("portscan_error", PortScanErrorEvent{
				ID:    id,
				Mode:  mode,
				Error: err.Error(),
			})
		}
	}()
	return true, nil
}

// ScanDevicePorts probes a device for open ports and persists the result.
// mode is "common" (default) or "deep" (ports 1–1024, capped).
func (e *Engine) ScanDevicePorts(ctx context.Context, id, mode string) ([]ports.ServicePort, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "common"
	}
	if mode != "common" && mode != "deep" {
		return nil, fmt.Errorf("invalid mode %q (use common or deep)", mode)
	}
	if !e.tryBeginPortScan(id) {
		return nil, ErrPortScanInProgress
	}
	defer e.endPortScan(id)
	return e.runPortScan(ctx, id, mode)
}

func (e *Engine) runPortScan(ctx context.Context, id, mode string) ([]ports.ServicePort, error) {
	dev, ok := e.GetDevice(id)
	if !ok {
		return nil, fmt.Errorf("device not found")
	}
	if dev.IP == "" {
		return nil, fmt.Errorf("device has no IP")
	}

	var open []ports.ServicePort
	switch mode {
	case "deep":
		open = ports.ScanPortsRange(ctx, dev.IP, ports.DefaultDeepStart, ports.DefaultDeepEnd, 128, 80*time.Millisecond)
	default:
		open = ports.ScanPorts(ctx, dev.IP)
	}

	e.mu.Lock()
	d, ok := e.devices[id]
	if !ok {
		e.mu.Unlock()
		return nil, fmt.Errorf("device not found")
	}
	d.OpenPorts = open
	out := *d
	e.mu.Unlock()

	e.persistDevice(out)
	e.recordEvent("portscan", out.ID, fmt.Sprintf("Port scan (%s): %d open", mode, len(open)))
	e.emitEvent("device_updated", &out)
	e.emitEvent("portscan_complete", PortScanCompleteEvent{
		ID:        out.ID,
		Mode:      mode,
		OpenPorts: open,
	})
	return open, nil
}
