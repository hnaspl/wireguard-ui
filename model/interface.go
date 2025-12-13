package model

import (
	"time"
)

// WgInterface model for managing multiple WireGuard interfaces
type WgInterface struct {
	ID                 string    `json:"id"`                  // e.g., "wg0", "wg1", "wg_friend"
	Name               string    `json:"name"`                // Human-readable name
	Type               string    `json:"type"`                // "server" or "client"
	InterfaceAddresses []string  `json:"interface_addresses"` // IP addresses for this interface
	PrivateKey         string    `json:"private_key"`
	PublicKey          string    `json:"public_key"`       // Auto-calculated from private key
	ListenPort         int       `json:"listen_port"`      // For server type interfaces
	MTU                int       `json:"mtu"`              // MTU setting
	Table              string    `json:"table"`            // Routing table ("off", "auto", or number) - defaults to "off" for Docker compatibility
	DNS                []string  `json:"dns"`              // DNS servers
	PostUpScript       string    `json:"post_up_script"`   // Custom PostUp script content
	PostDownScript     string    `json:"post_down_script"` // Custom PostDown script content
	ConfigFilePath     string    `json:"config_file_path"` // e.g., "/etc/wireguard/wg0.conf"
	Enabled            bool      `json:"enabled"`          // Whether interface is active
	IsDefault          bool      `json:"is_default"`       // Primary server interface (wg0)
	Created            time.Time `json:"created"`
	Updated            time.Time `json:"updated"`

	// For client-type interfaces (connecting to external servers)
	PeerPublicKey           string   `json:"peer_public_key,omitempty"`           // Remote server's public key
	PeerPresharedKey        string   `json:"peer_preshared_key,omitempty"`        // Optional preshared key
	PeerEndpoint            string   `json:"peer_endpoint,omitempty"`             // Remote server endpoint (host:port)
	PeerAllowedIPs          []string `json:"peer_allowed_ips,omitempty"`          // Routes through this peer
	PeerPersistentKeepalive int      `json:"peer_persistent_keepalive,omitempty"` // Keepalive interval

	// Advanced routing configuration
	AllowedInterfaces []string `json:"allowed_interfaces,omitempty"` // Interface IDs that can forward traffic to this interface
	RemoteNetworks    []string `json:"remote_networks,omitempty"`    // Networks reachable through this interface (CIDR notation)
	EnableSNAT        bool     `json:"enable_snat,omitempty"`        // Enable SNAT/MASQUERADE for RemoteNetworks
}

// WgInterfaceType constants
const (
	WgInterfaceTypeServer = "server"
	WgInterfaceTypeClient = "client"
)
