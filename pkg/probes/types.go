package probes

// UPnPInfo contains hardware and service details extracted from UPnP/SSDP device description XML.
type UPnPInfo struct {
	FriendlyName    string `json:"friendly_name,omitempty"`
	Manufacturer    string `json:"manufacturer,omitempty"`
	ModelName       string `json:"model_name,omitempty"`
	ModelNumber     string `json:"model_number,omitempty"`
	ModelDesc       string `json:"model_desc,omitempty"`
	DeviceType      string `json:"device_type,omitempty"`
	PresentationURL string `json:"presentation_url,omitempty"`
	ServerHeader    string `json:"server_header,omitempty"`
	Location        string `json:"location,omitempty"`
}

// NetBIOSInfo contains Windows computer name and workgroup/domain information.
type NetBIOSInfo struct {
	ComputerName string `json:"computer_name,omitempty"`
	Workgroup    string `json:"workgroup,omitempty"`
	UserName     string `json:"user_name,omitempty"`
	MAC          string `json:"mac,omitempty"`
}

// TLSInfo contains certificate identity details extracted from an HTTPS handshake.
type TLSInfo struct {
	Port      int      `json:"port"`
	SubjectCN string   `json:"subject_cn,omitempty"`
	SANs      []string `json:"sans,omitempty"`
	IssuerOrg string   `json:"issuer_org,omitempty"`
}

// RokuInfo contains identity reported by a Roku's ECP endpoint, including the
// owner-assigned device name.
type RokuInfo struct {
	Name         string `json:"name,omitempty"`
	ModelName    string `json:"model_name,omitempty"`
	ModelNumber  string `json:"model_number,omitempty"`
	VendorName   string `json:"vendor_name,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	SoftwareVer  string `json:"software_version,omitempty"`
}

// ProbeResult aggregates findings from all protocol probes executed against a target host.
type ProbeResult struct {
	IP      string       `json:"ip"`
	UPnP    *UPnPInfo    `json:"upnp,omitempty"`
	NetBIOS *NetBIOSInfo `json:"netbios,omitempty"`
	TLS     *TLSInfo     `json:"tls,omitempty"`
	Roku    *RokuInfo    `json:"roku,omitempty"`
}
