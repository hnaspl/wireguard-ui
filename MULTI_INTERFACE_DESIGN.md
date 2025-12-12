# Multi-Interface Support Design Document

## Executive Summary

This document outlines the design for adding multi-interface support to wireguard-ui, enabling users to manage multiple WireGuard interfaces (wg0, wg1, wg2, etc.) from a single UI. This feature allows connecting to external WireGuard servers as a client while maintaining the existing server functionality.

## Current Architecture Analysis

### Existing Single-Interface Design

**Current Implementation:**
- Manages ONE WireGuard interface (typically wg0)
- Single `Server` model with interface configuration
- All clients are peers on the same interface
- One private key per installation
- Configuration path: `/etc/wireguard/wg0.conf`

**Database Schema (Current):**
```
Server:
  - InterfaceAddresses (e.g., "10.100.100.1/24")
  - PrivateKey
  - ListenPort
  - MTU
  - DNS
  - PostUp/PostDown paths

Client:
  - Name
  - Email
  - AllocatedIPs
  - PublicKey
  - PresharedKey
  - Endpoint (optional - for site-to-site)
  - AllowedIPs
  - IsSiteToSite
```

**Current Features to Preserve:**
1. ✅ Site-to-site VPN (peers with endpoints on single interface)
2. ✅ Firewall rules management with per-client restrictions
3. ✅ Auto-generated PostUp/PostDown scripts
4. ✅ Per-client firewall rules with restriction enforcement
5. ✅ MSS clamping, protected IP blocking
6. ✅ Automatic WG_SUBNETS calculation

## Proposed Multi-Interface Architecture

### Design Goals

1. **Backward Compatibility**: Existing installations continue working without changes
2. **Interface Independence**: Each interface has its own configuration, clients, and firewall rules
3. **Unified Management**: Single UI for managing all interfaces
4. **Firewall Integration**: Firewall rules work correctly across multiple interfaces
5. **Status Monitoring**: Per-interface status and statistics

### Database Schema Changes

#### New `Interface` Model

```go
type Interface struct {
    ID               string    `json:"id"`               // e.g., "wg0", "wg1", "wg_friend"
    Name             string    `json:"name"`             // Human-readable name
    Type             string    `json:"type"`             // "server" or "client"
    InterfaceAddresses string  `json:"interface_addresses"`
    PrivateKey       string    `json:"private_key"`
    PublicKey        string    `json:"public_key"`       // Auto-calculated
    ListenPort       int       `json:"listen_port"`
    MTU              int       `json:"mtu"`
    DNS              string    `json:"dns"`
    PostUpScript     string    `json:"post_up_script"`
    PostDownScript   string    `json:"post_down_script"`
    ConfigFilePath   string    `json:"config_file_path"` // e.g., "/etc/wireguard/wg1.conf"
    Enabled          bool      `json:"enabled"`
    IsDefault        bool      `json:"is_default"`       // Primary server interface
    Created          time.Time `json:"created"`
    Updated          time.Time `json:"updated"`
}
```

**Interface Types:**
- **`server`**: Traditional server interface (wg0) - hosts clients
- **`client`**: Client connection to external server (wg1, wg2, etc.)

#### Modified `Client` Model

```go
type Client struct {
    // ... existing fields ...
    InterfaceID      string    `json:"interface_id"`     // Links to Interface.ID
    // ... rest unchanged ...
}
```

#### Modified `FirewallRule` Model

```go
type FirewallRule struct {
    // ... existing fields ...
    InterfaceID      string    `json:"interface_id"`     // Links to Interface.ID
    // ... rest unchanged ...
}
```

### Migration Strategy

**Phase 1: Database Migration**
```go
// Migration creates default interface from existing Server config
func MigrateToMultiInterface(db *gorm.DB) error {
    // 1. Read existing Server configuration
    var server model.Server
    db.First(&server)
    
    // 2. Create default "wg0" interface
    defaultInterface := model.Interface{
        ID:                 "wg0",
        Name:               "Default Server",
        Type:               "server",
        InterfaceAddresses: server.Interface.Addresses,
        PrivateKey:         server.KeyPair.PrivateKey,
        PublicKey:          server.KeyPair.PublicKey,
        ListenPort:         server.Interface.ListenPort,
        MTU:                server.Interface.Mtu,
        DNS:                server.Interface.DNS,
        PostUpScript:       server.Interface.PostUp,
        PostDownScript:     server.Interface.PostDown,
        ConfigFilePath:     "/etc/wireguard/wg0.conf",
        Enabled:            true,
        IsDefault:          true,
    }
    db.Create(&defaultInterface)
    
    // 3. Update all existing clients to reference wg0
    db.Model(&model.Client{}).Update("interface_id", "wg0")
    
    // 4. Update all existing firewall rules to reference wg0
    db.Model(&model.FirewallRule{}).Update("interface_id", "wg0")
    
    return nil
}
```

**Phase 2: Backward Compatibility Layer**
- Keep existing `Server` API endpoints working
- Map Server operations to default interface
- Gradual deprecation path for old APIs

### UI Architecture

#### New Interface Management Screen

**Location:** `/interfaces` (new menu item)

**Features:**
1. **Interface List View**
   ```
   [+ Add Interface]
   
   ┌─────────────────────────────────────────────────────┐
   │ wg0 - Default Server          [Type: Server]  [●]   │
   │ 10.100.100.1/24 | Listen: 51820 | MTU: 1420        │
   │ [View Clients] [Edit] [Status]                      │
   └─────────────────────────────────────────────────────┘
   
   ┌─────────────────────────────────────────────────────┐
   │ wg1 - Friend's VPN            [Type: Client]  [●]   │
   │ 10.0.0.13/24 | Endpoint: friend.com:51820           │
   │ [View Config] [Edit] [Status] [Disconnect]          │
   └─────────────────────────────────────────────────────┘
   ```

2. **Add External Connection Dialog**
   ```
   ┌─────────────────────────────────────────────────────┐
   │ Add External WireGuard Connection                    │
   ├─────────────────────────────────────────────────────┤
   │ Connection Name: [Friend's VPN___________]           │
   │                                                      │
   │ ═══ Your Configuration (sent by friend) ═══         │
   │ Address:      [10.0.0.13/24________________]         │
   │ Private Key:  [Generate New] or [Import______]       │
   │ DNS:          [10.0.0.1,64.6.64.6__________]         │
   │ MTU:          [1420]                                 │
   │                                                      │
   │ ═══ Friend's Server Configuration ═══                │
   │ Endpoint:     [friend.com:51820____________]         │
   │ Public Key:   [abc123...___________________]         │
   │ Preshared Key:[optional____________________]         │
   │ Allowed IPs:  [0.0.0.0/0,::/0______________]         │
   │ Persistent    [25]                                   │
   │   Keepalive:                                         │
   │                                                      │
   │ ☑ Enable immediately after creation                  │
   │                                                      │
   │           [Cancel]              [Create Connection]  │
   └─────────────────────────────────────────────────────┘
   ```

3. **Import from Config File**
   ```
   Paste WireGuard config:
   ┌─────────────────────────────────────────────────────┐
   │ [Interface]                                          │
   │ Address = 10.0.0.13/24                               │
   │ PrivateKey = <paste here>                            │
   │ DNS = 10.0.0.1                                       │
   │                                                      │
   │ [Peer]                                               │
   │ PublicKey = <paste here>                             │
   │ Endpoint = friend.com:51820                          │
   │ AllowedIPs = 0.0.0.0/0                               │
   └─────────────────────────────────────────────────────┘
   
   [Parse and Create]
   ```

#### Modified Existing Screens

**Wireguard Clients Screen:**
```
Interface Selector: [wg0 - Default Server ▼]

[+ New Client]  [🔥 Apply Config]

Client List (for selected interface)
...
```

**Firewall Rules Screen:**
```
Interface Selector: [wg0 - Default Server ▼]

[+ Add Rule]

Firewall Rules (for selected interface)
...
```

**Global Settings Screen:**
```
Interface Selector: [wg0 - Default Server ▼]

Settings for selected interface...
```

### Configuration Generation Logic

#### Per-Interface Config Files

**Server Interface (wg0):**
```ini
# Generated by wireguard-ui for interface wg0
[Interface]
Address = 10.100.100.1/24
PrivateKey = <server_private_key>
ListenPort = 51820
MTU = 1420
PostUp = /etc/wireguard/wg0-postup.sh
PostDown = /etc/wireguard/wg0-postdown.sh

[Peer]
# client1
PublicKey = <client1_public_key>
AllowedIPs = 10.100.100.2/32

[Peer]
# client2
PublicKey = <client2_public_key>
AllowedIPs = 10.100.100.3/32
```

**Client Interface (wg1):**
```ini
# Generated by wireguard-ui for interface wg1 (Friend's VPN)
[Interface]
Address = 10.0.0.13/24
PrivateKey = <generated_private_key>
DNS = 10.0.0.1,64.6.64.6
MTU = 1420
PostUp = /etc/wireguard/wg1-postup.sh
PostDown = /etc/wireguard/wg1-postdown.sh

[Peer]
PublicKey = <friend_server_public_key>
PresharedKey = <preshared_key_if_provided>
Endpoint = friend.com:51820
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 25
```

#### Modified Config Generation Function

```go
func GenerateInterfaceConfig(interfaceID string) (string, error) {
    // 1. Load interface
    var iface model.Interface
    db.Where("id = ?", interfaceID).First(&iface)
    
    // 2. Load clients/peers for this interface
    var clients []model.Client
    db.Where("interface_id = ?", interfaceID).Find(&clients)
    
    // 3. Generate config based on interface type
    if iface.Type == "server" {
        return generateServerConfig(iface, clients)
    } else {
        return generateClientConfig(iface)
    }
}
```

### Firewall Script Integration

#### Challenge: Multiple Interfaces with Different Traffic Patterns

**Key Considerations:**
1. Each interface needs its own firewall rules
2. Must prevent cross-interface rule conflicts
3. WG_SUBNETS calculation per interface
4. Protected IPs may differ per interface

#### Solution: Per-Interface Script Generation

**wg0-postup.sh (Server Interface):**
```bash
#!/bin/bash
set -e

IPT="/sbin/iptables"
WG_IF="wg0"
WG_SUBNETS="10.100.100.0/24"  # Auto-calculated from interface addresses
LAN_ALL="${LAN_ALL:-192.168.0.0/16}"
LAN_PROTECT="${LAN_PROTECT:-192.168.4.1/32}"
MASQ_OIF_PATTERN="${MASQ_OIF_PATTERN:-eth+}"

# INPUT chain rules
$IPT -C INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
$IPT -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

$IPT -C INPUT -i "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
$IPT -I INPUT 1 -i "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT

# FORWARD chain setup
$IPT -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
$IPT -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Block protected IPs
for PROTECT_IP in $LAN_PROTECT; do
    $IPT -C FORWARD -i "$WG_IF" -d "$PROTECT_IP" -j REJECT 2>/dev/null || \
    $IPT -I FORWARD 1 -i "$WG_IF" -d "$PROTECT_IP" -j REJECT
done

# --- FIREWALL RULES FROM UI (wg0) ---
# Per-client rules generated here...

# Allow WG <-> LAN traffic (unrestricted clients)
$IPT -C FORWARD -i "$WG_IF" -d "$LAN_ALL" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
$IPT -A FORWARD -i "$WG_IF" -d "$LAN_ALL" -m conntrack --ctstate NEW -j ACCEPT

$IPT -C FORWARD -s "$LAN_ALL" -o "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
$IPT -A FORWARD -s "$LAN_ALL" -o "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT

# MSS clamping
$IPT -t mangle -C FORWARD -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
$IPT -t mangle -A FORWARD -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Internet NAT (only for external traffic)
$IPT -t nat -C POSTROUTING -s "$WG_SUBNETS" -o $MASQ_OIF_PATTERN -j MASQUERADE 2>/dev/null || \
$IPT -t nat -A POSTROUTING -s "$WG_SUBNETS" -o $MASQ_OIF_PATTERN -j MASQUERADE
```

**wg1-postup.sh (Client Interface):**
```bash
#!/bin/bash
set -e

IPT="/sbin/iptables"
WG_IF="wg1"
WG_SUBNETS="10.0.0.0/24"  # Friend's network
LOCAL_IP="10.0.0.13/32"   # Your assigned IP

# Allow traffic from this interface
$IPT -C INPUT -i "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
$IPT -I INPUT 1 -i "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT

# Allow forwarding for this interface
$IPT -C FORWARD -i "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
$IPT -A FORWARD -i "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT

$IPT -C FORWARD -o "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
$IPT -A FORWARD -o "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT

# MSS clamping for this interface
$IPT -t mangle -C FORWARD -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
$IPT -t mangle -A FORWARD -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

#### Firewall Rule Generation Updates

```go
func GenerateAndSaveScripts(interfaceID string) error {
    var iface model.Interface
    db.Where("id = ?", interfaceID).First(&iface)
    
    // Generate interface-specific script paths
    postUpPath := fmt.Sprintf("/etc/wireguard/%s-postup.sh", interfaceID)
    postDownPath := fmt.Sprintf("/etc/wireguard/%s-postdown.sh", interfaceID)
    
    // Load firewall rules for this interface only
    var rules []model.FirewallRule
    db.Where("interface_id = ? AND enabled = ?", interfaceID, true).Find(&rules)
    
    // Generate scripts with interface-specific context
    postUpScript := generatePostUpScript(iface, rules)
    postDownScript := generatePostDownScript(iface, rules)
    
    // Save scripts
    os.WriteFile(postUpPath, []byte(postUpScript), 0755)
    os.WriteFile(postDownPath, []byte(postDownScript), 0755)
    
    return nil
}
```

### API Endpoints

#### New Interface Management APIs

```go
// List all interfaces
GET /api/interfaces
Response: []Interface

// Get specific interface
GET /api/interfaces/:id
Response: Interface

// Create new interface
POST /api/interfaces
Body: {
    "name": "Friend's VPN",
    "type": "client",
    "interface_addresses": "10.0.0.13/24",
    "private_key": "<generated_or_provided>",
    "dns": "10.0.0.1",
    "peer": {
        "public_key": "<friend_public_key>",
        "endpoint": "friend.com:51820",
        "allowed_ips": "0.0.0.0/0",
        "persistent_keepalive": 25
    }
}
Response: Interface

// Update interface
PUT /api/interfaces/:id
Body: Interface
Response: Interface

// Delete interface
DELETE /api/interfaces/:id
Response: 204 No Content

// Enable/disable interface
POST /api/interfaces/:id/toggle
Response: Interface

// Get interface status
GET /api/interfaces/:id/status
Response: {
    "interface": "wg1",
    "status": "up",
    "peers": [...],
    "transfer_rx": "1.2 GB",
    "transfer_tx": "543 MB"
}
```

#### Modified Existing APIs

All existing APIs gain optional `interface_id` parameter:
```go
// Clients
GET /api/clients?interface_id=wg0
POST /api/clients
Body: { ..., "interface_id": "wg0" }

// Firewall rules
GET /api/firewall-rules?interface_id=wg0
POST /api/firewall-rule
Body: { ..., "interface_id": "wg0" }
```

### Status Monitoring

#### Per-Interface Status

```go
func GetInterfaceStatus(interfaceID string) (*InterfaceStatus, error) {
    // Execute: wg show wg1
    output, err := exec.Command("wg", "show", interfaceID).Output()
    
    // Parse interface info
    status := &InterfaceStatus{
        Interface:  interfaceID,
        Status:     "up", // or "down"
        PublicKey:  parsePublicKey(output),
        ListenPort: parseListenPort(output),
        Peers:      parsePeers(output),
    }
    
    return status, nil
}
```

#### Status Display

**Interface List:**
```
┌─────────────────────────────────────────────────────┐
│ wg0 - Default Server                    Status: ●UP  │
│ 10.100.100.1/24 | Port: 51820                       │
│ Peers: 5 connected | RX: 1.2 GB | TX: 543 MB        │
│ Last handshake: 2 minutes ago                        │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│ wg1 - Friend's VPN                      Status: ●UP  │
│ 10.0.0.13/24 | Endpoint: friend.com:51820           │
│ Peer: friend-server | RX: 45 MB | TX: 12 MB         │
│ Last handshake: 30 seconds ago                       │
└─────────────────────────────────────────────────────┘
```

## Implementation Roadmap

### Phase 1: Database Schema & Migration (Week 1)
- [ ] Create `Interface` model
- [ ] Add `InterfaceID` foreign keys to `Client` and `FirewallRule`
- [ ] Write migration script
- [ ] Test migration with existing installations

### Phase 2: Backend API (Week 2)
- [ ] Implement interface CRUD handlers
- [ ] Update client/firewall APIs for multi-interface
- [ ] Modify config generation for per-interface
- [ ] Update firewall script generation

### Phase 3: UI Components (Week 3)
- [ ] Create interface management screen
- [ ] Add "Import Config" dialog
- [ ] Implement interface selector in existing screens
- [ ] Update navigation menu

### Phase 4: Status & Monitoring (Week 4)
- [ ] Per-interface status monitoring
- [ ] Interface enable/disable functionality
- [ ] Connection health indicators
- [ ] Logs per interface

### Phase 5: Testing & Documentation (Week 5)
- [ ] End-to-end testing
- [ ] Migration testing
- [ ] User documentation
- [ ] API documentation

## Testing Strategy

### Unit Tests

```go
func TestInterfaceCreation(t *testing.T) {
    // Test creating new interface
    iface := model.Interface{
        ID:   "wg1",
        Name: "Test Interface",
        Type: "client",
        ...
    }
    
    err := db.Create(&iface).Error
    assert.NoError(t, err)
}

func TestConfigGeneration(t *testing.T) {
    // Test config generation for different interface types
}

func TestFirewallScriptGeneration(t *testing.T) {
    // Test script generation with multiple interfaces
}
```

### Integration Tests

```bash
# Test migration
./wireguard-ui migrate

# Test interface creation
curl -X POST /api/interfaces -d '{...}'

# Test config application
curl -X POST /api/apply-config

# Verify interfaces are up
wg show all
```

### Manual Testing Checklist

- [ ] Existing single-interface installation migrates correctly
- [ ] New external connection can be created via UI
- [ ] Config files generated correctly for each interface
- [ ] Firewall rules apply to correct interface
- [ ] Status monitoring shows correct data
- [ ] Interface can be enabled/disabled
- [ ] Multiple client interfaces work simultaneously
- [ ] No conflicts between interface firewall rules

## Risk Mitigation

### Backward Compatibility Risks

**Risk:** Existing installations break after upgrade

**Mitigation:**
1. Comprehensive migration testing
2. Backup recommendation before upgrade
3. Rollback capability
4. Keep old API endpoints functional

### Firewall Rule Conflicts

**Risk:** iptables rules from different interfaces conflict

**Mitigation:**
1. Use interface-specific chains
2. Careful rule ordering
3. Test with multiple interfaces active
4. Clear documentation on rule precedence

### Configuration Errors

**Risk:** Invalid configs prevent WireGuard startup

**Mitigation:**
1. Config validation before save
2. Test config with `wg-quick` before applying
3. Rollback on error
4. Clear error messages

## Reference: Original PostUp/PostDown Scripts

### Original postup.sh (for reference)

```bash
#!/bin/bash
set -e

IPT="/sbin/iptables"
WG_IF="wg0"
WG_SUBNETS="10.100.100.0/24"
LAN_ALL="192.168.0.0/16"
LAN_PROTECT="192.168.4.1/32"
MASQ_OIF_PATTERN="eth+"

# INPUT: Accept established/related
$IPT -C INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
$IPT -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# INPUT: Accept ICMP
$IPT -C INPUT -p icmp -j ACCEPT 2>/dev/null || \
$IPT -I INPUT 1 -p icmp -j ACCEPT

# INPUT: Accept from WireGuard
$IPT -C INPUT -i "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
$IPT -I INPUT 1 -i "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT

# INPUT: Accept service ports (22, 80, 9090, 9100, 9633)
for PORT in 22 80 9090 9100 9633; do
    $IPT -C INPUT -p tcp --dport $PORT -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
    $IPT -I INPUT 1 -p tcp --dport $PORT -m conntrack --ctstate NEW -j ACCEPT
done

# FORWARD: Accept established/related
$IPT -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
$IPT -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# FORWARD: Block protected IPs
for PROTECT_IP in $LAN_PROTECT; do
    $IPT -C FORWARD -i "$WG_IF" -d "$PROTECT_IP" -j REJECT 2>/dev/null || \
    $IPT -I FORWARD 1 -i "$WG_IF" -d "$PROTECT_IP" -j REJECT
done

# FORWARD: Allow WG -> LAN
$IPT -C FORWARD -i "$WG_IF" -d "$LAN_ALL" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
$IPT -A FORWARD -i "$WG_IF" -d "$LAN_ALL" -m conntrack --ctstate NEW -j ACCEPT

# FORWARD: Allow LAN -> WG
$IPT -C FORWARD -s "$LAN_ALL" -o "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
$IPT -A FORWARD -s "$LAN_ALL" -o "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT

# MSS clamping (bidirectional)
$IPT -t mangle -C FORWARD -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
$IPT -t mangle -A FORWARD -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

$IPT -t mangle -C FORWARD -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
$IPT -t mangle -A FORWARD -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# MSS clamping (OUTPUT for locally-originated packets)
$IPT -t mangle -C OUTPUT -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
$IPT -t mangle -A OUTPUT -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# NAT: Masquerade to internet (not to LAN)
$IPT -t nat -C POSTROUTING -s "$WG_SUBNETS" -o $MASQ_OIF_PATTERN -j MASQUERADE 2>/dev/null || \
$IPT -t nat -A POSTROUTING -s "$WG_SUBNETS" -o $MASQ_OIF_PATTERN -j MASQUERADE
```

### Original postdown.sh (for reference)

```bash
#!/bin/bash

IPT="/sbin/iptables"
WG_IF="wg0"
WG_SUBNETS="10.100.100.0/24"
LAN_ALL="192.168.0.0/16"
LAN_PROTECT="192.168.4.1/32"
MASQ_OIF_PATTERN="eth+"

# Remove INPUT rules
$IPT -D INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
$IPT -D INPUT -p icmp -j ACCEPT 2>/dev/null || true
$IPT -D INPUT -i "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || true

for PORT in 22 80 9090 9100 9633; do
    $IPT -D INPUT -p tcp --dport $PORT -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || true
done

# Remove FORWARD rules
$IPT -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

for PROTECT_IP in $LAN_PROTECT; do
    $IPT -D FORWARD -i "$WG_IF" -d "$PROTECT_IP" -j REJECT 2>/dev/null || true
done

$IPT -D FORWARD -i "$WG_IF" -d "$LAN_ALL" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || true
$IPT -D FORWARD -s "$LAN_ALL" -o "$WG_IF" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || true

# Remove MSS clamping
$IPT -t mangle -D FORWARD -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
$IPT -t mangle -D FORWARD -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
$IPT -t mangle -D OUTPUT -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

# Remove NAT
$IPT -t nat -D POSTROUTING -s "$WG_SUBNETS" -o $MASQ_OIF_PATTERN -j MASQUERADE 2>/dev/null || true
```

## Security Considerations

### Private Key Management

- Each interface has unique private key
- Keys stored securely in database
- Option to import existing keys
- Auto-generation for new interfaces

### Firewall Isolation

- Rules scoped to specific interfaces
- No cross-interface rule leakage
- Protected IPs enforced per interface
- Clear audit trail

### Access Control

- Per-interface permissions (future enhancement)
- Admin can control which users manage which interfaces
- Audit logging for config changes

## Performance Considerations

### Database Queries

- Index on `interface_id` foreign keys
- Eager loading of related data
- Caching of interface configurations

### iptables Rules

- Minimize rule count
- Use efficient matching
- Regular cleanup of stale rules

## Documentation Requirements

### User Documentation

1. **Migration Guide**: How to upgrade existing installation
2. **External Connection Setup**: Step-by-step guide with screenshots
3. **Troubleshooting**: Common issues and solutions
4. **Best Practices**: Recommendations for multi-interface setups

### Developer Documentation

1. **API Reference**: All new endpoints documented
2. **Database Schema**: ER diagrams and relationships
3. **Code Architecture**: Component interactions
4. **Testing Guide**: How to run tests

## Conclusion

This design enables wireguard-ui to support multiple WireGuard interfaces while maintaining backward compatibility and preserving all existing features including firewall rules, site-to-site VPN, and auto-generated scripts. The architecture is extensible and follows established patterns in the codebase.

**Key Benefits:**
- ✅ Connect to external WireGuard servers as a client
- ✅ Maintain existing server functionality
- ✅ Per-interface firewall rules
- ✅ Clean separation of concerns
- ✅ Backward compatible
- ✅ Comprehensive testing strategy

**Next Steps:**
1. Review and approve design document
2. Create implementation tickets
3. Begin Phase 1 development
4. Iterate based on feedback
