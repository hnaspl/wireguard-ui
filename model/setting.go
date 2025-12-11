package model

import (
	"time"
)

// GlobalSetting model
type GlobalSetting struct {
	EndpointAddress     string    `json:"endpoint_address"`
	DNSServers          []string  `json:"dns_servers"`
	MTU                 int       `json:"mtu,string"`
	PersistentKeepalive int       `json:"persistent_keepalive,string"`
	FirewallMark        string    `json:"firewall_mark"`
	Table               string    `json:"table"`
	ConfigFilePath      string    `json:"config_file_path"`
	PostUpTemplate      string    `json:"post_up_template"`
	PostDownTemplate    string    `json:"post_down_template"`
	// Environment variables for PostUp/PostDown scripts
	// Note: WgSubnets is automatically calculated from server interface addresses, not stored
	LanAll           string `json:"lan_all"`              // e.g., "192.168.0.0/16"
	LanProtect       string `json:"lan_protect"`          // e.g., "192.168.4.1/32"
	MasqOifPattern   string `json:"masq_oif_pattern"`     // e.g., "eth+"
	PostUpScriptPath string `json:"post_up_script_path"`  // Path to external script
	PostDownScriptPath string `json:"post_down_script_path"` // Path to external script
	EnableAutoGenScripts bool `json:"enable_auto_gen_scripts"` // Auto-generate PostUp/PostDown from firewall rules
	UpdatedAt        time.Time `json:"updated_at"`
}
