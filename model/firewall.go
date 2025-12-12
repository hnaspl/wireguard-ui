package model

import (
	"time"
)

// FirewallRule model
type FirewallRule struct {
	ID          string    `json:"id"`
	ClientID    string    `json:"client_id"`
	ClientName  string    `json:"client_name,omitempty"` // For display purposes
	InterfaceID string    `json:"interface_id"`          // Links to Interface.ID - which interface this rule applies to
	AllowedIP   string    `json:"allowed_ip"`
	AllowedPort string    `json:"allowed_port"` // Can be single port or range (e.g., "80" or "80:443" or "any")
	Protocol    string    `json:"protocol"`     // tcp, udp, or any
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
