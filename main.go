package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/jaredwarren/Gofing/pkg/engine"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/server"
	"github.com/jaredwarren/Gofing/pkg/store"
	"github.com/jaredwarren/Gofing/web"
)

func main() {
	portFlag := flag.Int("port", 8080, "Port for the web interface")
	intervalFlag := flag.Duration("interval", 30*time.Second, "Background network rescan interval")
	openBrowserFlag := flag.Bool("open", true, "Auto open browser on startup")
	dataDirFlag := flag.String("data-dir", "", "Data directory (default: ~/Library/Application Support/Gofing)")
	flag.Parse()

	slog.Info("⚡ Starting Gofing Local Network Discovery Service...")

	dbPath := store.DefaultDBPath()
	if *dataDirFlag != "" {
		dbPath = filepath.Join(*dataDirFlag, "gofing.db")
	}

	db, err := store.Open(dbPath)
	if err != nil {
		slog.Error("❌ Failed to open store", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("💾 Store initialized", "path", dbPath)

	netInfo, err := network.GetActiveNetworkInfo()
	if err != nil {
		slog.Error("❌ Error detecting active network", "error", err)
		os.Exit(1)
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
	devEngine.SetActiveNetwork(netInfo)
	slog.Info("📂 Loaded known devices from store", "count", len(devEngine.GetDevices()), "network", engine.NetworkKeyFromInfo(netInfo))

	go func() {
		slog.Info("🔍 Performing initial subnet scan...")
		devices, err := devEngine.PerformScan(ctx, netInfo)
		if err != nil {
			slog.Warn("⚠️ Initial scan error", "error", err)
		} else {
			slog.Info("✅ Initial scan completed", "discovered_devices", len(devices))
		}
	}()

	go func() {
		ticker := time.NewTicker(*intervalFlag)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if currentInfo, err := network.GetActiveNetworkInfo(); err == nil {
					_, _ = devEngine.PerformScan(ctx, currentInfo)
				}
			}
		}
	}()

	staticFS, err := web.GetStaticFS()
	if err != nil {
		slog.Error("❌ Failed to load embedded web assets", "error", err)
		os.Exit(1)
	}

	httpServer := server.New(devEngine, staticFS)
	addr := fmt.Sprintf(":%d", *portFlag)
	url := fmt.Sprintf("http://localhost:%d", *portFlag)

	srv := &http.Server{
		Addr:    addr,
		Handler: httpServer.Handler(),
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("🚀 Gofing Web Interface running", "url", url)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("❌ Server error", "error", err)
			os.Exit(1)
		}
	}()

	if *openBrowserFlag {
		go openBrowser(url)
	}

	<-stop
	slog.Info("🛑 Shutting down Gofing service gracefully...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("⚠️ HTTP shutdown error", "error", err)
	}
	slog.Info("👋 Store closed. Shutdown complete.")
}

func openBrowser(url string) {
	time.Sleep(500 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	}
	if cmd != nil {
		_ = cmd.Run()
	}
}
