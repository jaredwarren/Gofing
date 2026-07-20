package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/jaredwarren/Gofing/pkg/engine"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/server"
	"github.com/jaredwarren/Gofing/web"
)

func main() {
	portFlag := flag.Int("port", 8080, "Port for the web interface")
	intervalFlag := flag.Duration("interval", 30*time.Second, "Background network rescan interval")
	openBrowserFlag := flag.Bool("open", true, "Auto open browser on startup")
	flag.Parse()

	log.Println("⚡ Starting Gofing Local Network Discovery Service...")

	netInfo, err := network.GetActiveNetworkInfo()
	if err != nil {
		log.Fatalf("❌ Error detecting active network: %v", err)
	}

	log.Printf("🌐 Active Network Interface: %s (IP: %s, Subnet: %s, Gateway: %s, SSID: %s)",
		netInfo.InterfaceName, netInfo.IP, netInfo.SubnetCIDR, netInfo.GatewayIP, netInfo.SSID)

	devEngine := engine.New()

	// Perform initial scan asynchronously
	go func() {
		log.Println("🔍 Performing initial subnet scan...")
		devices, err := devEngine.PerformScan(netInfo)
		if err != nil {
			log.Printf("⚠️ Initial scan error: %v", err)
		} else {
			log.Printf("✅ Initial scan completed. Discovered %d devices.", len(devices))
		}
	}()

	// Start continuous background rescan ticker
	go func() {
		ticker := time.NewTicker(*intervalFlag)
		defer ticker.Stop()

		for range ticker.C {
			if currentInfo, err := network.GetActiveNetworkInfo(); err == nil {
				_, _ = devEngine.PerformScan(currentInfo)
			}
		}
	}()

	staticFS, err := web.GetStaticFS()
	if err != nil {
		log.Fatalf("❌ Failed to load embedded web assets: %v", err)
	}

	httpServer := server.New(devEngine, staticFS)
	addr := fmt.Sprintf(":%d", *portFlag)
	url := fmt.Sprintf("http://localhost:%d", *portFlag)

	log.Printf("🚀 Gofing Web Interface running at %s", url)

	if *openBrowserFlag {
		go openBrowser(url)
	}

	if err := http.ListenAndServe(addr, httpServer.Handler()); err != nil {
		log.Fatalf("❌ Server error: %v", err)
	}
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
