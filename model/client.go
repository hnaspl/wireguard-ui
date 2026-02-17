package model

import (
	"time"
)

// Client model
type Client struct {
	ID              string    `json:"id"`
	PrivateKey      string    `json:"private_key"`
	PublicKey       string    `json:"public_key"`
	PresharedKey    string    `json:"preshared_key"`
	Name            string    `json:"name"`
	TgUserid        string    `json:"telegram_userid"`
	Email           string    `json:"email"`
	SubnetRanges    []string  `json:"subnet_ranges,omitempty"`
	AllocatedIPs    []string  `json:"allocated_ips"`
	AllowedIPs      []string  `json:"allowed_ips"`
	ExtraAllowedIPs []string  `json:"extra_allowed_ips"`
	Endpoint        string    `json:"endpoint"`
	InterfaceID     string    `json:"interface_id"` // Links to Interface.ID - which interface this client belongs to
	AdditionalNotes string    `json:"additional_notes"`
	UseServerDNS    bool      `json:"use_server_dns"`
	Enabled         bool      `json:"enabled"`
	IsSiteToSite    bool      `json:"is_site_to_site"`
	AllowWebAccess  bool      `json:"allow_web_access"`  // Allow ports 80, 443 even when client has firewall rules
	AllowDNSAccess  bool      `json:"allow_dns_access"`  // Allow port 53 (UDP/TCP) even when client has firewall rules
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ClientData includes the Client and extra data
type ClientData struct {
	Client *Client
	QRCode string
}

type QRCodeSettings struct {
	Enabled    bool
	IncludeDNS bool
	IncludeMTU bool
}
