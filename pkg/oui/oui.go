package oui

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed nmap-mac-prefixes
var rawPrefixes string

const cacheFileName = "oui_cache.json"
const legacyCacheFileName = "mac_cache.json"

type macLookupResponse struct {
	Success   bool   `json:"success"`
	Found     bool   `json:"found"`
	Company   string `json:"company"`
	IsRand    bool   `json:"isRand"`
	IsPrivate bool   `json:"isPrivate"`
}

// DB encapsulates the IEEE OUI prefix map and persistent vendor cache.
type DB struct {
	ouiMap     map[string]string
	diskCache  map[string]string
	cacheMu    sync.RWMutex
	dir        string
	httpClient *http.Client
}

var (
	defaultDB       *DB
	defaultDBOnce   sync.Once
	dataDirOverride string // test hook override
)

// DefaultDB returns the global default OUI database instance.
func DefaultDB() *DB {
	defaultDBOnce.Do(func() {
		dir := dataDir()
		defaultDB = NewDB(dir)
	})
	return defaultDB
}

// NewDB creates an initialized DB using the specified data directory for cache persistence.
func NewDB(dir string) *DB {
	db := &DB{
		ouiMap:     make(map[string]string, 55000),
		diskCache:  make(map[string]string),
		dir:        dir,
		httpClient: &http.Client{Timeout: 1500 * time.Millisecond},
	}
	db.initMap()
	return db
}

func (db *DB) initMap() {
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
				db.ouiMap[prefix] = vendor
			}
		}
	}

	// 2. Load persistent disk cache if present
	db.loadDiskCache()
}

func dataDir() string {
	if dataDirOverride != "" {
		return dataDirOverride
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".", "GofingData")
	}
	return filepath.Join(home, "Library", "Application Support", "Gofing")
}

func (db *DB) cachePath() string {
	dir := db.dir
	if dir == "" {
		dir = dataDir()
	}
	return filepath.Join(dir, cacheFileName)
}

func cachePath() string {
	return DefaultDB().cachePath()
}

func (db *DB) loadDiskCache() {
	cPath := db.cachePath()
	if data, err := os.ReadFile(cPath); err == nil {
		var loaded map[string]string
		if err := json.Unmarshal(data, &loaded); err == nil {
			db.diskCache = loaded
			return
		}
	}

	// One-time migration from legacy cwd mac_cache.json.
	if data, err := os.ReadFile(legacyCacheFileName); err == nil {
		var loaded map[string]string
		if err := json.Unmarshal(data, &loaded); err == nil {
			db.diskCache = loaded
			db.saveDiskCache()
		}
	}
}

func (db *DB) saveDiskCache() {
	dir := db.dir
	if dir == "" {
		dir = dataDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(db.diskCache, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(db.cachePath(), data, 0o644)
}

// LookupVendor returns the vendor string for a MAC using the default DB instance.
func LookupVendor(mac string) string {
	return DefaultDB().LookupVendor(mac)
}

// LookupVendorLocal resolves a vendor from the embedded IEEE database and the
// disk cache only, never over the network. Returns "" on a miss so a caller on
// a latency-sensitive path can defer the HTTP lookup to a background tier.
func LookupVendorLocal(mac string) string {
	return DefaultDB().LookupVendorLocal(mac)
}

// LookupVendorLocal is the network-free half of LookupVendor. A miss returns "".
func (db *DB) LookupVendorLocal(mac string) string {
	if mac == "" {
		return "Unknown Vendor"
	}

	clean := cleanMACPrefix(mac)
	if len(clean) < 6 {
		return "Generic Device"
	}
	prefix := clean[:6]

	// 1. Embedded 52,000+ entry IEEE database.
	if vendor, found := db.ouiMap[prefix]; found && vendor != "" {
		return normalizeVendor(vendor)
	}

	// 2. Disk cache of prior API answers.
	db.cacheMu.RLock()
	cachedVendor, foundInCache := db.diskCache[prefix]
	db.cacheMu.RUnlock()
	if foundInCache {
		return cachedVendor
	}

	return ""
}

// cleanMACPrefix strips separators and upper-cases a MAC for prefix lookups.
func cleanMACPrefix(mac string) string {
	clean := strings.ToUpper(mac)
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, ".", "")
	return clean
}

// LookupVendor checks embedded DB -> disk cache -> maclookup.app API on the DB instance.
func (db *DB) LookupVendor(mac string) string {
	if mac == "" {
		return "Unknown Vendor"
	}

	clean := cleanMACPrefix(mac)
	if len(clean) < 6 {
		return "Generic Device"
	}
	prefix := clean[:6]

	// 1+2. Embedded IEEE database, then the disk cache.
	if local := db.LookupVendorLocal(mac); local != "" {
		return local
	}

	// 3. Check locally if it's a randomized private MAC
	if isRandomizedMAC(clean) {
		result := "Private / Randomized MAC"
		db.cacheMu.Lock()
		db.diskCache[prefix] = result
		db.saveDiskCache()
		db.cacheMu.Unlock()
		return result
	}

	// 4. Query maclookup.app API with the OUI prefix only (never the full MAC).
	apiVendor := db.queryMACLookupAPI(prefix)
	if apiVendor != "" {
		norm := normalizeVendor(apiVendor)
		db.cacheMu.Lock()
		db.diskCache[prefix] = norm
		db.saveDiskCache()
		db.cacheMu.Unlock()
		return norm
	}

	return "Generic Device"
}

// queryMACLookupAPI asks maclookup.app for a vendor. cleanPrefix must be the
// 6-hex OUI only — never a full MAC — so a unique NIC address is not disclosed.
func (db *DB) queryMACLookupAPI(cleanPrefix string) string {
	if len(cleanPrefix) < 6 {
		return ""
	}
	prefix := cleanPrefix[:6]
	url := "https://api.maclookup.app/v2/macs/" + prefix
	resp, err := db.httpClient.Get(url)
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
