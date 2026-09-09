package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jaredwarren/Gofing/pkg/dhcp"
	"github.com/jaredwarren/Gofing/pkg/engine"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/server"
	"github.com/jaredwarren/Gofing/pkg/store"
	"github.com/jaredwarren/Gofing/web"
)

func main() {
	portFlag := flag.Int("port", 8080, "Port for the web interface")
	intervalFlag := flag.Duration("interval", 5*time.Minute, "Deprecated: seeds the Tier-2 discovery sweep interval; prefer PATCH /api/settings")
	openFlag := flag.Bool("open", true, "Open a desktop GUI window on startup")
	dataDirFlag := flag.String("data-dir", "", "Data directory (default: ~/Library/Application Support/Gofing)")
	dhcpFileFlag := flag.String("dhcp-file", "", "DHCP client-list file to poll (default: <data-dir>/dhcp-clients.txt if present)")
	dhcpURLFlag := flag.String("dhcp-url", "", "HTTP URL returning DHCP leases as JSON or a client-list export")
	dhcpIntervalFlag := flag.Duration("dhcp-interval", 60*time.Second, "DHCP lease poll interval")
	flag.Parse()

	setupLogging(*openFlag)
	if os.Getenv("GOFING_DEBUG") != "" {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr,
			&slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	url := fmt.Sprintf("http://127.0.0.1:%d", *portFlag)
	slog.Info("⚡ Starting Gofing Local Network Discovery Service...")

	// Second Dock click while already running: reopen the UI instead of dying on the DB lock.
	if *openFlag && httpReachable(url) {
		slog.Info("Gofing already running; reopening window", "url", url)
		runWindow(url)
		return
	}

	dbPath := store.DefaultDBPath()
	if *dataDirFlag != "" {
		dbPath = filepath.Join(*dataDirFlag, "gofing.db")
	}

	db, err := store.Open(dbPath)
	if err != nil {
		if *openFlag && httpReachable(url) {
			slog.Warn("Store locked but server reachable; reopening window", "error", err)
			runWindow(url)
			return
		}
		fail("Failed to open store", err, *openFlag)
	}
	defer db.Close()
	slog.Info("💾 Store initialized", "path", dbPath)

	netInfo, err := network.GetActiveNetworkInfo()
	if err != nil {
		fail("Error detecting active network", err, *openFlag)
	}

	slog.Info("🌐 Active Network Interface",
		"iface", netInfo.InterfaceName,
		"ip", netInfo.IP,
		"subnet", netInfo.SubnetCIDR,
		"gateway", netInfo.GatewayIP,
		"ssid", netInfo.SSID,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	devEngine := engine.New(db)

	// -interval predates the settings API. Honour it when explicitly passed,
	// but do not let its default silently override a stored preference.
	intervalSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "interval" {
			intervalSet = true
		}
	})
	if intervalSet {
		sec := int(intervalFlag.Seconds())
		if _, err := devEngine.UpdateSettings(engine.SettingsPatch{ScanIntervalSec: &sec}); err != nil {
			slog.Warn("failed to seed discovery interval from -interval", "error", err)
		} else {
			slog.Info("discovery interval seeded from -interval", "sec", sec)
		}
	}

	devEngine.Start(ctx, netInfo)
	slog.Info("📂 Loaded known devices from store", "count", len(devEngine.GetDevices()), "network", engine.NetworkKeyFromInfo(netInfo))

	dhcpFile := *dhcpFileFlag
	if dhcpFile == "" {
		dhcpFile = filepath.Join(filepath.Dir(dbPath), "dhcp-clients.txt")
	}
	go pollDHCP(ctx, devEngine, dhcp.Source{File: dhcpFile, URL: *dhcpURLFlag}, *dhcpIntervalFlag)

	staticFS, err := web.GetStaticFS()
	if err != nil {
		fail("Failed to load embedded web assets", err, *openFlag)
	}

	httpServer := server.New(devEngine, staticFS)
	addr := fmt.Sprintf(":%d", *portFlag)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if *openFlag && httpReachable(url) {
			slog.Warn("Port in use but server reachable; reopening window", "error", err)
			runWindow(url)
			return
		}
		fail("Failed to listen on "+addr, err, *openFlag)
	}

	srv := &http.Server{Handler: httpServer.Handler()}

	go func() {
		slog.Info("🚀 Gofing Web Interface running", "url", url)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("❌ Server error", "error", err)
			if *openFlag {
				alert("Gofing", "Server error: "+err.Error())
			}
			os.Exit(1)
		}
	}()

	shutdown := func() {
		slog.Info("🛑 Shutting down Gofing service gracefully...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("⚠️ HTTP shutdown error", "error", err)
		}
		slog.Info("👋 Store closed. Shutdown complete.")
	}

	if !*openFlag {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		shutdown()
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		slog.Info("Signal received, terminating application...")
		terminateNativeApp()
	}()

	// Give the HTTP server a moment to bind before the window opens.
	time.Sleep(200 * time.Millisecond)
	if !httpReachable(url) {
		fail("HTTP server did not become ready", fmt.Errorf("no response from %s", url), true)
	}
	runWindow(url)
	shutdown()
}

func pollDHCP(ctx context.Context, eng *engine.Engine, src dhcp.Source, interval time.Duration) {
	run := func() {
		leases, err := src.Fetch(ctx)
		if err != nil {
			slog.Warn("DHCP poll failed", "error", err)
			return
		}
		if len(leases) == 0 {
			return
		}
		res := eng.ImportDHCPLeases(leases)
		if res.Created == 0 && res.Updated == 0 {
			return
		}
		slog.Info("DHCP leases imported", "parsed", len(leases), "created", res.Created, "updated", res.Updated, "skipped", res.Skipped)
	}

	run()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

// runWindow opens a native desktop window pointing to the local server.
func runWindow(targetURL string) {
	// Set native macOS Dock icon via Cocoa runtime
	if pngBytes, err := web.GetIconPNG(); err == nil && len(pngBytes) > 0 {
		setNativeDockIcon(pngBytes)
	}

	slog.Info("Native desktop window active; closing it will terminate this Gofing process")
	runNativeWindow(targetURL)
	slog.Info("Native window closed")
}

func httpReachable(url string) bool {
	client := &http.Client{Timeout: 400 * time.Millisecond}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

func setupLogging(gui bool) {
	if !gui {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	logDir := filepath.Join(home, "Library", "Logs", "Gofing")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(logDir, "gofing.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	// Keep process alive ownership of the file; slog writes for the process lifetime.
	mw := io.MultiWriter(os.Stderr, f)
	slog.SetDefault(slog.New(slog.NewTextHandler(mw, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

func fail(msg string, err error, gui bool) {
	slog.Error("❌ "+msg, "error", err)
	if gui {
		detail := msg
		if err != nil {
			detail = msg + ": " + err.Error()
		}
		alert("Gofing", detail)
	}
	os.Exit(1)
}

func alert(title, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	script := fmt.Sprintf(`display alert %q message %q as critical`, title, truncate(message, 400))
	_ = exec.CommandContext(ctx, "osascript", "-e", script).Run()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
