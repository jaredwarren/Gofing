package oui

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed nmap-mac-prefixes
var rawPrefixes string

const cacheFileName = "mac_cache.json"

type macLookupResponse struct {
	Success   bool   `json:"success"`
	Found     bool   `json:"found"`
	Company   string `json:"company"`
	IsRand    bool   `json:"isRand"`
	IsPrivate bool   `json:"isPrivate"`
}

var (
	ouiMap     map[string]string
	diskCache  map[string]string
	cacheMu    sync.RWMutex
	initOnce   sync.Once
	httpClient = &http.Client{Timeout: 1500 * time.Millisecond}
)

func initMap() {
	ouiMap = make(map[string]string, 55000)
	diskCache = make(map[string]string)

	// 1. Load embedded Nmap OUI database
	scanner := bufio.NewScanner(strings.NewReader(rawPrefixes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			prefix := strings.ToUpper(fields[0])
			if len(prefix) == 6 {
				vendor := strings.Join(fields[1:], " ")
				ouiMap[prefix] = vendor
			}
		}
	}

	// 2. Load persistent disk cache if present
	loadDiskCache()
}

func loadDiskCache() {
	data, err := os.ReadFile(cacheFileName)
	if err == nil {
		var loaded map[string]string
		if err := json.Unmarshal(data, &loaded); err == nil {
			diskCache = loaded
		}
	}
}

func saveDiskCache() {
	data, err := json.MarshalIndent(diskCache, "", "  ")
	if err == nil {
		_ = os.WriteFile(cacheFileName, data, 0644)
	}
}

// LookupVendor checks embedded DB -> disk cache -> maclookup.app API.
func LookupVendor(mac string) string {
	initOnce.Do(initMap)

	if mac == "" {
		return "Unknown Vendor"
	}

	clean := strings.ToUpper(mac)
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, ".", "")

	if len(clean) < 6 {
		return "Generic Device"
	}

	prefix := clean[:6]

	// 1. Check embedded 52,000+ IEEE database
	if vendor, found := ouiMap[prefix]; found && vendor != "" {
		return normalizeVendor(vendor)
	}

	// 2. Check disk cache
	cacheMu.RLock()
	cachedVendor, foundInCache := diskCache[prefix]
	cacheMu.RUnlock()

	if foundInCache {
		return cachedVendor
	}

	// 3. Check locally if it's a randomized private MAC
	if isRandomizedMAC(clean) {
		result := "Private / Randomized MAC"
		cacheMu.Lock()
		diskCache[prefix] = result
		saveDiskCache()
		cacheMu.Unlock()
		return result
	}

	// 4. Query maclookup.app API
	apiVendor := queryMACLookupAPI(clean)
	if apiVendor != "" {
		norm := normalizeVendor(apiVendor)
		cacheMu.Lock()
		diskCache[prefix] = norm
		saveDiskCache()
		cacheMu.Unlock()
		return norm
	}

	return "Generic Device"
}

func queryMACLookupAPI(cleanMAC string) string {
	url := "https://api.maclookup.app/v2/macs/" + cleanMAC
	resp, err := httpClient.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var res macLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err == nil {
		if res.IsRand || res.IsPrivate {
			return "Private / Randomized MAC"
		}
		if res.Success && res.Found && res.Company != "" {
			return res.Company
		}
	}

	return ""
}

// isRandomizedMAC checks if the 2nd hex digit of MAC is 2, 6, A, or E (locally administered bit).
func isRandomizedMAC(cleanMAC string) bool {
	if len(cleanMAC) < 2 {
		return false
	}
	secondChar := cleanMAC[1]
	return secondChar == '2' || secondChar == '6' || secondChar == 'A' || secondChar == 'E'
}

func normalizeVendor(raw string) string {
	v := strings.TrimSpace(raw)
	vLower := strings.ToLower(v)

	if strings.Contains(vLower, "apple") {
		return "Apple, Inc."
	}
	if strings.Contains(vLower, "parallels") {
		return "Parallels (Virtual Mac)"
	}
	if strings.Contains(vLower, "raspberry pi") {
		return "Raspberry Pi Trading Ltd"
	}
	if strings.Contains(vLower, "eero") {
		return "eero (Amazon)"
	}
	if strings.Contains(vLower, "amazon") || strings.Contains(vLower, "ring") {
		return "Amazon / Ring"
	}
	if strings.Contains(vLower, "google") || strings.Contains(vLower, "nest") {
		return "Google / Nest"
	}
	if strings.Contains(vLower, "sonos") {
		return "Sonos, Inc."
	}
	if strings.Contains(vLower, "samsung") {
		return "Samsung Electronics"
	}
	if strings.Contains(vLower, "tp-link") {
		return "TP-Link Technologies"
	}
	if strings.Contains(vLower, "netgear") {
		return "Netgear"
	}
	if strings.Contains(vLower, "ubiquiti") {
		return "Ubiquiti Inc."
	}
	if strings.Contains(vLower, "cisco") || strings.Contains(vLower, "linksys") {
		return "Cisco Systems"
	}
	if strings.Contains(vLower, "espressif") {
		return "Espressif Inc."
	}
	if strings.Contains(vLower, "intel") {
		return "Intel Corporation"
	}
	if strings.Contains(vLower, "sony") {
		return "Sony Corporation"
	}
	if strings.Contains(vLower, "lg ele") || vLower == "lg" {
		return "LG Electronics"
	}
	if strings.Contains(vLower, "nintendo") {
		return "Nintendo Co., Ltd."
	}
	if strings.Contains(vLower, "roku") {
		return "Roku, Inc."
	}
	if strings.Contains(vLower, "hp ") || vLower == "hp" || strings.Contains(vLower, "hewlett") {
		return "HP Inc."
	}
	if strings.Contains(vLower, "dell") {
		return "Dell Inc."
	}
	if strings.Contains(vLower, "lenovo") {
		return "Lenovo"
	}
	if strings.Contains(vLower, "asus") {
		return "ASUSTek Computer"
	}
	if strings.Contains(vLower, "broadcom") {
		return "Broadcom"
	}
	if strings.Contains(vLower, "realtek") {
		return "Realtek Semiconductor"
	}
	if strings.Contains(vLower, "tuya") {
		return "Tuya Smart"
	}
	if strings.Contains(vLower, "wyze") {
		return "Wyze Labs"
	}
	if strings.Contains(vLower, "philips") {
		return "Philips Lighting / Hue"
	}

	return v
}
