package util

import (
	"fmt"
	"os"
	"strings"

	"github.com/ngoduykhanh/wireguard-ui/model"
)

// GenerateFirewallRules generates iptables commands from UI firewall rules
// These are inserted AFTER established/related and protected IP rules
// Returns: accept rules, drop rules for restricted clients, list of restricted client IPs
func GenerateFirewallRules(firewallRules []model.FirewallRule, clients []model.ClientData, action string, iface *model.WgInterface) (string, string, []string) {
	if len(firewallRules) == 0 {
		// No firewall rules = clients get full access via broad FORWARD rules
		// Don't add web/DNS rules even if checkboxes are enabled
		return "", "", []string{}
	}

	var acceptRules []string
	var dropRules []string
	clientIPMap := make(map[string][]string)
	clientsWithRules := make(map[string]bool) // Track which clients have firewall rules

	// Build map of client ID to their allocated IPs
	for _, clientData := range clients {
		if clientData.Client != nil && clientData.Client.Enabled {
			clientIPMap[clientData.Client.ID] = clientData.Client.AllocatedIPs
		}
	}

	// Generate ACCEPT rules for each firewall rule
	for _, rule := range firewallRules {
		if !rule.Enabled {
			continue
		}

		clientIPs, exists := clientIPMap[rule.ClientID]
		if !exists || len(clientIPs) == 0 {
			continue
		}

		// Mark this client as having firewall rules
		clientsWithRules[rule.ClientID] = true

		// For each client IP, generate appropriate iptables rule
		for _, clientIP := range clientIPs {
			// Strip CIDR notation if present for source matching
			sourceIP := strings.Split(clientIP, "/")[0]

			var cmd string
			if action == "add" {
				cmd = "$IPT -I FORWARD 1"
			} else {
				cmd = "$IPT -D FORWARD"
			}

			// Build the iptables command - using -m conntrack for new connections
			ruleCmd := fmt.Sprintf("%s -i \"$WG_IF\" -s %s -d %s", cmd, sourceIP, rule.AllowedIP)

			// Add protocol if not "any"
			if rule.Protocol != "any" && rule.Protocol != "" {
				ruleCmd += fmt.Sprintf(" -p %s", rule.Protocol)
			}

			// Add port if not "any"
			if rule.AllowedPort != "any" && rule.AllowedPort != "" {
				if rule.Protocol == "tcp" || rule.Protocol == "udp" {
					// Remove spaces after commas for port lists
					ports := strings.ReplaceAll(rule.AllowedPort, ", ", ",")
					ports = strings.ReplaceAll(ports, " ", "")
					
					// Check if multiple ports (contains comma)
					if strings.Contains(ports, ",") {
						// Multiple ports require multiport module
						ruleCmd += fmt.Sprintf(" -m multiport --dports %s", ports)
					} else {
						// Single port
						ruleCmd += fmt.Sprintf(" --dport %s", ports)
					}
				}
			}

			ruleCmd += " -m conntrack --ctstate NEW -j ACCEPT"

			acceptRules = append(acceptRules, ruleCmd)
		}
	}

	// Build map of client ID to client object for web/DNS access checking
	clientObjMap := make(map[string]*model.Client)
	for _, clientData := range clients {
		if clientData.Client != nil && clientData.Client.Enabled {
			clientObjMap[clientData.Client.ID] = clientData.Client
		}
	}

	// Generate DROP rules for clients that have firewall rules configured
	// This enforces "if firewall rules exist, only allow what's specified"
	var restrictedIPs []string
	for clientID := range clientsWithRules {
		clientIPs, exists := clientIPMap[clientID]
		if !exists || len(clientIPs) == 0 {
			continue
		}

		// Get the client object for per-client web/DNS access settings
		clientObj := clientObjMap[clientID]

		for _, clientIP := range clientIPs {
			// Strip CIDR notation if present
			sourceIP := strings.Split(clientIP, "/")[0]
			restrictedIPs = append(restrictedIPs, sourceIP)
			
			// Add web/DNS access for clients with firewall rules if client has these flags enabled
			// (Only add for restricted clients - unrestricted clients get full access anyway)
			if clientObj != nil {
				if clientObj.AllowWebAccess {
					// Allow HTTP and HTTPS for this specific client
					var cmd string
					if action == "add" {
						cmd = "$IPT -I FORWARD 1"
					} else {
						cmd = "$IPT -D FORWARD"
					}
					
					webHTTPRule := fmt.Sprintf("%s -i \"$WG_IF\" -s %s -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT", cmd, sourceIP)
					webHTTPSRule := fmt.Sprintf("%s -i \"$WG_IF\" -s %s -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT", cmd, sourceIP)
					acceptRules = append(acceptRules, webHTTPRule, webHTTPSRule)
				}
				
				if clientObj.AllowDNSAccess {
					// Allow DNS UDP and TCP for this specific client
					var cmd string
					if action == "add" {
						cmd = "$IPT -I FORWARD 1"
					} else {
						cmd = "$IPT -D FORWARD"
					}
					
					dnsUDPRule := fmt.Sprintf("%s -i \"$WG_IF\" -s %s -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT", cmd, sourceIP)
					dnsTCPRule := fmt.Sprintf("%s -i \"$WG_IF\" -s %s -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT", cmd, sourceIP)
					acceptRules = append(acceptRules, dnsUDPRule, dnsTCPRule)
				}
			}

			var cmd string
			if action == "add" {
				cmd = "$IPT -A FORWARD"
			} else {
				cmd = "$IPT -D FORWARD"
			}

			// DROP any other NEW connections from this client
			dropCmd := fmt.Sprintf("%s -i \"$WG_IF\" -s %s -m conntrack --ctstate NEW -j DROP", cmd, sourceIP)
			dropRules = append(dropRules, dropCmd)
		}
	}

	// Add check to avoid duplicates when using -I (insert) mode for ACCEPT rules
	var acceptRulesWithChecks []string
	for _, rule := range acceptRules {
		if action == "add" {
			// Replace -I with -C for check, then add the rule only if check fails
			checkRule := strings.Replace(rule, "$IPT -I FORWARD 1", "$IPT -C FORWARD", 1)
			safeRule := fmt.Sprintf("%s 2>/dev/null || \\\n%s", checkRule, rule)
			acceptRulesWithChecks = append(acceptRulesWithChecks, safeRule)
		} else {
			// For delete, add || true to ignore errors if rule doesn't exist
			acceptRulesWithChecks = append(acceptRulesWithChecks, rule+" 2>/dev/null || true")
		}
	}

	// Add check for DROP rules
	var dropRulesWithChecks []string
	for _, rule := range dropRules {
		if action == "add" {
			// Replace -A with -C for check, then add the rule only if check fails
			checkRule := strings.Replace(rule, "$IPT -A FORWARD", "$IPT -C FORWARD", 1)
			safeRule := fmt.Sprintf("%s 2>/dev/null || \\\n%s", checkRule, rule)
			dropRulesWithChecks = append(dropRulesWithChecks, safeRule)
		} else {
			// For delete, add || true to ignore errors if rule doesn't exist
			dropRulesWithChecks = append(dropRulesWithChecks, rule+" 2>/dev/null || true")
		}
	}

	return strings.Join(acceptRulesWithChecks, "\n"), strings.Join(dropRulesWithChecks, "\n"), restrictedIPs
}

// GeneratePostUpScript generates a complete PostUp script matching the user's pattern
func GeneratePostUpScriptWithRouting(globalSettings model.GlobalSetting, wgSubnets string, firewallRules []model.FirewallRule, clients []model.ClientData, interfaceName string, iface *model.WgInterface, allInterfaces []model.WgInterface) string {
	var script strings.Builder

	// Start with environment variable setup (matching user's pattern)
	wgIf := interfaceName
	if wgIf == "" {
		wgIf = "${INTERFACE:-wg0}"
	}

	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -eu\n\n")
	script.WriteString(fmt.Sprintf("WG_IF=\"%s\"\n", wgIf))
	
	// For client-type interfaces, only generate inter-interface routing rules
	if iface != nil && iface.Type == model.WgInterfaceTypeClient {
		return generateClientPostUpScript(wgIf, iface, allInterfaces)
	}
	
	// Set defaults matching user's script
	// wgSubnets is now calculated from server interface addresses
	if wgSubnets == "" {
		wgSubnets = "10.100.100.0/24"
	}
	script.WriteString(fmt.Sprintf("WG_SUBNETS=\"${WG_SUBNETS:-%s}\"\n", wgSubnets))
	
	lanAll := globalSettings.LanAll
	if lanAll == "" {
		lanAll = "192.168.0.0/16"
	}
	script.WriteString(fmt.Sprintf("LAN_ALL=\"${LAN_ALL:-%s}\"\n", lanAll))
	
	lanProtect := globalSettings.LanProtect
	if lanProtect == "" {
		lanProtect = "192.168.4.1/32"
	}
	script.WriteString(fmt.Sprintf("LAN_PROTECT=\"${LAN_PROTECT:-%s}\"\n", lanProtect))
	
	masqPattern := globalSettings.MasqOifPattern
	if masqPattern == "" {
		masqPattern = "eth+"
	}
	script.WriteString(fmt.Sprintf("MASQ_OIF_PATTERN=\"${MASQ_OIF_PATTERN:-%s}\"\n\n", masqPattern))

	script.WriteString("IPT=\"$(command -v iptables || echo iptables)\"\n")
	script.WriteString("SYS=/proc/sys\n\n")

	script.WriteString("echo \"[postup] IF=$WG_IF  WG_SUBNETS='$WG_SUBNETS'  LAN_ALL=$LAN_ALL  PROTECT=$LAN_PROTECT  MASQ_IF=$MASQ_OIF_PATTERN\"\n\n")

	// Route for WG subnets (matching user's pattern)
	script.WriteString("# Route for WG subnets\n")
	script.WriteString("for WG_SUB in $WG_SUBNETS; do\n")
	script.WriteString("  ip -4 route replace \"$WG_SUB\" dev \"$WG_IF\" 2>/dev/null || true\n")
	script.WriteString("done\n\n")

	// INPUT chain rules (matching user's pattern)
	script.WriteString("# --- INPUT (to the container itself) ---\n")
	script.WriteString("# accept established first\n")
	script.WriteString("$IPT -C INPUT -i \"$WG_IF\" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \\\n")
	script.WriteString("$IPT -I INPUT 1 -i \"$WG_IF\" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	script.WriteString("# ping from peers\n")
	script.WriteString("$IPT -C INPUT -i \"$WG_IF\" -p icmp -j ACCEPT 2>/dev/null || \\\n")
	script.WriteString("$IPT -I INPUT 1 -i \"$WG_IF\" -p icmp -j ACCEPT\n")
	script.WriteString("# common TCP services\n")
	script.WriteString("for P in 22 80 9090 9100 9633; do\n")
	script.WriteString("  $IPT -C INPUT -i \"$WG_IF\" -p tcp --dport \"$P\" -j ACCEPT 2>/dev/null || \\\n")
	script.WriteString("  $IPT -I INPUT 1 -i \"$WG_IF\" -p tcp --dport \"$P\" -j ACCEPT\n")
	script.WriteString("done\n\n")

	// FORWARD chain rules (matching user's pattern)
	script.WriteString("# --- FORWARD (through the container) ---\n")
	script.WriteString("# put ESTABLISHED,RELATED right at the top\n")
	script.WriteString("$IPT -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \\\n")
	script.WriteString("$IPT -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n\n")

	// Protected IP blocking (matching user's pattern)
	script.WriteString("# block NEW from wg -> your router IP specifically\n")
	script.WriteString("$IPT -C FORWARD -i \"$WG_IF\" -d \"$LAN_PROTECT\" -m conntrack --ctstate NEW -j DROP 2>/dev/null || \\\n")
	script.WriteString("$IPT -I FORWARD 1 -i \"$WG_IF\" -d \"$LAN_PROTECT\" -m conntrack --ctstate NEW -j DROP\n\n")

	// Add generated firewall rules from UI (these go after ESTABLISHED and PROTECT)
	if len(firewallRules) > 0 {
		script.WriteString("# --- FIREWALL RULES FROM UI ---\n")
		acceptRules, dropRules, _ := GenerateFirewallRules(firewallRules, clients, "add", iface)
		if acceptRules != "" {
			script.WriteString("# Allow specific traffic for clients with firewall rules\n")
			script.WriteString(acceptRules)
			script.WriteString("\n\n")
		}
		if dropRules != "" {
			script.WriteString("# Drop all other NEW traffic from clients with firewall rules\n")
			script.WriteString("# (Clients without firewall rules get broad access via rules below)\n")
			script.WriteString(dropRules)
			script.WriteString("\n\n")
		}
	}

	// WG_SUBNETS loop (matching user's pattern exactly)
	script.WriteString("for WG_SUB in $WG_SUBNETS; do\n")
	script.WriteString("  # MSS clamp both directions LAN<->WG\n")
	script.WriteString("  $IPT -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -s \"$LAN_ALL\" -d \"$WG_SUB\" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \\\n")
	script.WriteString("  $IPT -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -s \"$LAN_ALL\" -d \"$WG_SUB\" -j TCPMSS --clamp-mss-to-pmtu\n")
	script.WriteString("  $IPT -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -s \"$WG_SUB\" -d \"$LAN_ALL\" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \\\n")
	script.WriteString("  $IPT -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -s \"$WG_SUB\" -d \"$LAN_ALL\" -j TCPMSS --clamp-mss-to-pmtu\n\n")

	script.WriteString("  # also clamp locally-originating SYNs out wg0\n")
	script.WriteString("  $IPT -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -o \"$WG_IF\" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \\\n")
	script.WriteString("  $IPT -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -o \"$WG_IF\" -j TCPMSS --clamp-mss-to-pmtu\n\n")

	script.WriteString("  # Do NOT NAT either way between WG and LANs\n")
	script.WriteString("  $IPT -t nat -C POSTROUTING -s \"$WG_SUB\" -d \"$LAN_ALL\" -j RETURN 2>/dev/null || \\\n")
	script.WriteString("  $IPT -t nat -I POSTROUTING 1 -s \"$WG_SUB\" -d \"$LAN_ALL\" -j RETURN\n")
	script.WriteString("  $IPT -t nat -C POSTROUTING -s \"$LAN_ALL\" -d \"$WG_SUB\" -j RETURN 2>/dev/null || \\\n")
	script.WriteString("  $IPT -t nat -I POSTROUTING 1 -s \"$LAN_ALL\" -d \"$WG_SUB\" -j RETURN\n\n")

	script.WriteString("  # allow NEW LAN -> WG\n")
	script.WriteString("  $IPT -C FORWARD -o \"$WG_IF\" -s \"$LAN_ALL\" -d \"$WG_SUB\" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \\\n")
	script.WriteString("  $IPT -I FORWARD 1 -o \"$WG_IF\" -s \"$LAN_ALL\" -d \"$WG_SUB\" -m conntrack --ctstate NEW -j ACCEPT\n")
	script.WriteString("  # allow NEW WG -> LAN (router protection rule above still applies)\n")
	script.WriteString("  $IPT -C FORWARD -i \"$WG_IF\" -s \"$WG_SUB\" -d \"$LAN_ALL\" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \\\n")
	script.WriteString("  $IPT -I FORWARD 1 -i \"$WG_IF\" -s \"$WG_SUB\" -d \"$LAN_ALL\" -m conntrack --ctstate NEW -j ACCEPT\n")
	script.WriteString("done\n\n")

	// Broad fallbacks (matching user's pattern)
	script.WriteString("# broad fallbacks\n")
	script.WriteString("$IPT -C FORWARD -i \"$WG_IF\" -j ACCEPT 2>/dev/null || $IPT -A FORWARD -i \"$WG_IF\" -j ACCEPT\n")
	script.WriteString("$IPT -C FORWARD -o \"$WG_IF\" -j ACCEPT 2>/dev/null || $IPT -A FORWARD -o \"$WG_IF\" -j ACCEPT\n\n")

	// Add inter-interface routing rules if configured
	if iface != nil && len(iface.RemoteNetworks) > 0 {
		script.WriteString("# --- INTER-INTERFACE ROUTING ---\n")
		script.WriteString(fmt.Sprintf("# Remote networks accessible via %s: %s\n", interfaceName, strings.Join(iface.RemoteNetworks, ", ")))
		script.WriteString("\n")

		// Allow traffic from LAN to remote networks via this interface
		for _, remoteNet := range iface.RemoteNetworks {
			script.WriteString(fmt.Sprintf("# Allow LAN/macvlan -> %s to %s\n", interfaceName, remoteNet))
			script.WriteString(fmt.Sprintf("$IPT -C FORWARD -o \"$WG_IF\" -d %s -j ACCEPT 2>/dev/null || \\\n", remoteNet))
			script.WriteString(fmt.Sprintf("$IPT -I FORWARD 1 -o \"$WG_IF\" -d %s -j ACCEPT\n", remoteNet))
			script.WriteString(fmt.Sprintf("$IPT -C FORWARD -i \"$WG_IF\" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \\\n"))
			script.WriteString(fmt.Sprintf("$IPT -I FORWARD 1 -i \"$WG_IF\" -m state --state ESTABLISHED,RELATED -j ACCEPT\n\n"))
		}

		// Allow traffic from other allowed interfaces to remote networks via this interface
		if len(iface.AllowedInterfaces) > 0 {
			// Build map of interface IDs to names for lookup
			ifaceMap := make(map[string]string)
			for _, otherIface := range allInterfaces {
				ifaceMap[otherIface.ID] = otherIface.ID
			}

			for _, allowedIfaceID := range iface.AllowedInterfaces {
				if _, exists := ifaceMap[allowedIfaceID]; !exists {
					continue // Skip if interface doesn't exist
				}

				for _, remoteNet := range iface.RemoteNetworks {
					script.WriteString(fmt.Sprintf("# Allow %s -> %s to reach %s\n", allowedIfaceID, interfaceName, remoteNet))
					script.WriteString(fmt.Sprintf("$IPT -C FORWARD -i %s -o \"$WG_IF\" -d %s -j ACCEPT 2>/dev/null || \\\n", allowedIfaceID, remoteNet))
					script.WriteString(fmt.Sprintf("$IPT -I FORWARD 1 -i %s -o \"$WG_IF\" -d %s -j ACCEPT\n", allowedIfaceID, remoteNet))
					script.WriteString(fmt.Sprintf("$IPT -C FORWARD -i \"$WG_IF\" -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \\\n", allowedIfaceID))
					script.WriteString(fmt.Sprintf("$IPT -I FORWARD 1 -i \"$WG_IF\" -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT\n\n", allowedIfaceID))
				}
			}
		}

		// Add SNAT/MASQUERADE if enabled
		if iface.EnableSNAT {
			script.WriteString(fmt.Sprintf("# SNAT out of %s so remote sees traffic from interface IP (no extra routes needed on their LAN)\n", interfaceName))
			script.WriteString(fmt.Sprintf("$IPT -t nat -C POSTROUTING -o \"$WG_IF\" -j MASQUERADE 2>/dev/null || \\\n"))
			script.WriteString(fmt.Sprintf("$IPT -t nat -A POSTROUTING -o \"$WG_IF\" -j MASQUERADE\n\n"))
		}
	}

	// Internet masquerading (matching user's pattern)
	script.WriteString("# Internet MASQUERADE\n")
	script.WriteString("$IPT -t nat -C POSTROUTING -o \"$MASQ_OIF_PATTERN\" -j MASQUERADE 2>/dev/null || \\\n")
	script.WriteString("$IPT -t nat -A POSTROUTING -o \"$MASQ_OIF_PATTERN\" -j MASQUERADE\n\n")

	// Add custom template if provided
	if globalSettings.PostUpTemplate != "" && globalSettings.PostUpScriptPath == "" {
		script.WriteString("# Custom PostUp commands from template\n")
		script.WriteString(globalSettings.PostUpTemplate)
		script.WriteString("\n\n")
	}

	script.WriteString("echo \"[postup] done\"\n")

	return script.String()
}

// GeneratePostDownScript generates a complete PostDown script matching the user's pattern
func GeneratePostDownScriptWithRouting(globalSettings model.GlobalSetting, wgSubnets string, firewallRules []model.FirewallRule, clients []model.ClientData, interfaceName string, iface *model.WgInterface, allInterfaces []model.WgInterface) string {
	var script strings.Builder

	wgIf := interfaceName
	if wgIf == "" {
		wgIf = "${INTERFACE:-wg0}"
	}

	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -eu\n\n")
	script.WriteString(fmt.Sprintf("WG_IF=\"%s\"\n", wgIf))
	
	// For client-type interfaces, only generate inter-interface routing rules cleanup
	if iface != nil && iface.Type == model.WgInterfaceTypeClient {
		return generateClientPostDownScript(wgIf, iface, allInterfaces)
	}
	
	// Set defaults matching user's script
	// wgSubnets is now calculated from server interface addresses
	if wgSubnets == "" {
		wgSubnets = "10.100.100.0/24"
	}
	script.WriteString(fmt.Sprintf("WG_SUBNETS=\"${WG_SUBNETS:-%s}\"\n", wgSubnets))
	
	lanAll := globalSettings.LanAll
	if lanAll == "" {
		lanAll = "192.168.0.0/16"
	}
	script.WriteString(fmt.Sprintf("LAN_ALL=\"${LAN_ALL:-%s}\"\n", lanAll))
	
	lanProtect := globalSettings.LanProtect
	if lanProtect == "" {
		lanProtect = "192.168.4.1/32"
	}
	script.WriteString(fmt.Sprintf("LAN_PROTECT=\"${LAN_PROTECT:-%s}\"\n", lanProtect))
	
	masqPattern := globalSettings.MasqOifPattern
	if masqPattern == "" {
		masqPattern = "eth+"
	}
	script.WriteString(fmt.Sprintf("MASQ_OIF_PATTERN=\"${MASQ_OIF_PATTERN:-%s}\"\n\n", masqPattern))

	script.WriteString("IPT=\"$(command -v iptables || echo iptables)\"\n\n")

	script.WriteString("echo \"[postdown] IF=$WG_IF  WG_SUBNETS='$WG_SUBNETS'  LAN_ALL=$LAN_ALL  PROTECT=$LAN_PROTECT  MASQ_IF=$MASQ_OIF_PATTERN\"\n\n")

	// INPUT deletions (matching user's pattern)
	script.WriteString("# INPUT deletions\n")
	script.WriteString("$IPT -D INPUT -i \"$WG_IF\" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true\n")
	script.WriteString("$IPT -D INPUT -i \"$WG_IF\" -p icmp -j ACCEPT 2>/dev/null || true\n")
	script.WriteString("for P in 22 80 9090 9100 9633; do\n")
	script.WriteString("  $IPT -D INPUT -i \"$WG_IF\" -p tcp --dport \"$P\" -j ACCEPT 2>/dev/null || true\n")
	script.WriteString("done\n\n")

	// FORWARD deletions (matching user's pattern)
	script.WriteString("# FORWARD deletions\n")
	script.WriteString("$IPT -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true\n")
	script.WriteString("$IPT -D FORWARD -i \"$WG_IF\" -d \"$LAN_PROTECT\" -m conntrack --ctstate NEW -j DROP 2>/dev/null || true\n\n")

	// Remove generated firewall rules from UI
	if len(firewallRules) > 0 {
		script.WriteString("# Remove firewall rules from UI\n")
		acceptRules, dropRules, _ := GenerateFirewallRules(firewallRules, clients, "delete", iface)
		// Remove DROP rules first, then ACCEPT rules
		if dropRules != "" {
			script.WriteString(dropRules)
			script.WriteString("\n")
		}
		if acceptRules != "" {
			script.WriteString(acceptRules)
			script.WriteString("\n\n")
		}
	}

	// WG_SUBNETS loop (matching user's pattern)
	script.WriteString("for WG_SUB in $WG_SUBNETS; do\n")
	script.WriteString("  $IPT -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -s \"$LAN_ALL\" -d \"$WG_SUB\" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true\n")
	script.WriteString("  $IPT -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -s \"$WG_SUB\" -d \"$LAN_ALL\" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true\n")
	script.WriteString("  $IPT -t mangle -D OUTPUT  -p tcp --tcp-flags SYN,RST SYN -o \"$WG_IF\" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true\n\n")

	script.WriteString("  $IPT -t nat -D POSTROUTING -s \"$WG_SUB\" -d \"$LAN_ALL\" -j RETURN 2>/dev/null || true\n")
	script.WriteString("  $IPT -t nat -D POSTROUTING -s \"$LAN_ALL\" -d \"$WG_SUB\" -j RETURN 2>/dev/null || true\n\n")

	script.WriteString("  $IPT -D FORWARD -o \"$WG_IF\" -s \"$LAN_ALL\" -d \"$WG_SUB\" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || true\n")
	script.WriteString("  $IPT -D FORWARD -i \"$WG_IF\" -s \"$WG_SUB\" -d \"$LAN_ALL\" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || true\n")
	script.WriteString("done\n\n")

	// Remove fallbacks
	script.WriteString("$IPT -D FORWARD -i \"$WG_IF\" -j ACCEPT 2>/dev/null || true\n")
	script.WriteString("$IPT -D FORWARD -o \"$WG_IF\" -j ACCEPT 2>/dev/null || true\n\n")

	// Remove inter-interface routing rules if configured
	if iface != nil && len(iface.RemoteNetworks) > 0 {
		script.WriteString("# Remove inter-interface routing rules\n")

		// Remove SNAT if it was enabled
		if iface.EnableSNAT {
			script.WriteString(fmt.Sprintf("$IPT -t nat -D POSTROUTING -o \"$WG_IF\" -j MASQUERADE 2>/dev/null || true\n\n"))
		}

		// Remove traffic rules from other allowed interfaces
		if len(iface.AllowedInterfaces) > 0 {
			ifaceMap := make(map[string]string)
			for _, otherIface := range allInterfaces {
				ifaceMap[otherIface.ID] = otherIface.ID
			}

			for _, allowedIfaceID := range iface.AllowedInterfaces {
				if _, exists := ifaceMap[allowedIfaceID]; !exists {
					continue
				}

				for _, remoteNet := range iface.RemoteNetworks {
					script.WriteString(fmt.Sprintf("$IPT -D FORWARD -i %s -o \"$WG_IF\" -d %s -j ACCEPT 2>/dev/null || true\n", allowedIfaceID, remoteNet))
					script.WriteString(fmt.Sprintf("$IPT -D FORWARD -i \"$WG_IF\" -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true\n", allowedIfaceID))
				}
			}
		}

		// Remove LAN to remote networks rules
		for _, remoteNet := range iface.RemoteNetworks {
			script.WriteString(fmt.Sprintf("$IPT -D FORWARD -o \"$WG_IF\" -d %s -j ACCEPT 2>/dev/null || true\n", remoteNet))
			script.WriteString(fmt.Sprintf("$IPT -D FORWARD -i \"$WG_IF\" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true\n"))
		}
		script.WriteString("\n")
	}

	// Remove masquerading
	script.WriteString("$IPT -t nat -D POSTROUTING -o \"$MASQ_OIF_PATTERN\" -j MASQUERADE 2>/dev/null || true\n\n")

	// Add custom template if provided
	if globalSettings.PostDownTemplate != "" && globalSettings.PostDownScriptPath == "" {
		script.WriteString("# Custom PostDown commands from template\n")
		script.WriteString(globalSettings.PostDownTemplate)
		script.WriteString("\n\n")
	}

	script.WriteString("echo \"[postdown] done\"\n")

	return script.String()
}

// GeneratePostUpScript is a backward-compatible wrapper
func GeneratePostUpScript(globalSettings model.GlobalSetting, wgSubnets string, firewallRules []model.FirewallRule, clients []model.ClientData, interfaceName string) string {
	return GeneratePostUpScriptWithRouting(globalSettings, wgSubnets, firewallRules, clients, interfaceName, nil, nil)
}

// GeneratePostDownScript is a backward-compatible wrapper  
func GeneratePostDownScript(globalSettings model.GlobalSetting, wgSubnets string, firewallRules []model.FirewallRule, clients []model.ClientData, interfaceName string) string {
	return GeneratePostDownScriptWithRouting(globalSettings, wgSubnets, firewallRules, clients, interfaceName, nil, nil)
}

// generateClientPostUpScript generates a simplified PostUp script for client-type interfaces
// Only includes inter-interface routing rules, not the full server-style firewall
func generateClientPostUpScript(wgIf string, iface *model.WgInterface, allInterfaces []model.WgInterface) string {
	var script strings.Builder
	
	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -eu\n\n")
	script.WriteString(fmt.Sprintf("WG_IF=\"%s\"\n", wgIf))
	script.WriteString("IPT=\"$(command -v iptables || echo iptables)\"\n\n")
	
	script.WriteString("echo \"[postup] Client interface $WG_IF starting up\"\n\n")
	
	// Only add inter-interface routing rules if configured
	if iface != nil && len(iface.RemoteNetworks) > 0 {
		script.WriteString("# --- INTER-INTERFACE ROUTING ---\n")
		script.WriteString(fmt.Sprintf("# Remote networks accessible via %s: %s\n", wgIf, strings.Join(iface.RemoteNetworks, ", ")))
		script.WriteString("\n")

		// Allow traffic from LAN to remote networks via this interface
		for _, remoteNet := range iface.RemoteNetworks {
			script.WriteString(fmt.Sprintf("# Allow LAN/macvlan -> %s to %s\n", wgIf, remoteNet))
			script.WriteString(fmt.Sprintf("$IPT -C FORWARD -o \"$WG_IF\" -d %s -j ACCEPT 2>/dev/null || \\\n", remoteNet))
			script.WriteString(fmt.Sprintf("$IPT -I FORWARD 1 -o \"$WG_IF\" -d %s -j ACCEPT\n", remoteNet))
			script.WriteString(fmt.Sprintf("$IPT -C FORWARD -i \"$WG_IF\" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \\\n"))
			script.WriteString(fmt.Sprintf("$IPT -I FORWARD 1 -i \"$WG_IF\" -m state --state ESTABLISHED,RELATED -j ACCEPT\n\n"))
		}

		// Allow traffic from other allowed interfaces to remote networks via this interface
		if len(iface.AllowedInterfaces) > 0 {
			// Build map of interface IDs to names for lookup
			ifaceMap := make(map[string]string)
			for _, otherIface := range allInterfaces {
				ifaceMap[otherIface.ID] = otherIface.ID
			}

			for _, allowedIfaceID := range iface.AllowedInterfaces {
				if _, exists := ifaceMap[allowedIfaceID]; !exists {
					continue // Skip if interface doesn't exist
				}

				for _, remoteNet := range iface.RemoteNetworks {
					script.WriteString(fmt.Sprintf("# Allow %s -> %s to reach %s\n", allowedIfaceID, wgIf, remoteNet))
					script.WriteString(fmt.Sprintf("$IPT -C FORWARD -i %s -o \"$WG_IF\" -d %s -j ACCEPT 2>/dev/null || \\\n", allowedIfaceID, remoteNet))
					script.WriteString(fmt.Sprintf("$IPT -I FORWARD 1 -i %s -o \"$WG_IF\" -d %s -j ACCEPT\n", allowedIfaceID, remoteNet))
					script.WriteString(fmt.Sprintf("$IPT -C FORWARD -i \"$WG_IF\" -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \\\n", allowedIfaceID))
					script.WriteString(fmt.Sprintf("$IPT -I FORWARD 1 -i \"$WG_IF\" -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT\n\n", allowedIfaceID))
				}
			}
		}

		// Add SNAT/MASQUERADE if enabled
		if iface.EnableSNAT {
			script.WriteString(fmt.Sprintf("# SNAT out of %s so remote sees traffic from interface IP (no extra routes needed on their LAN)\n", wgIf))
			script.WriteString(fmt.Sprintf("$IPT -t nat -C POSTROUTING -o \"$WG_IF\" -j MASQUERADE 2>/dev/null || \\\n"))
			script.WriteString(fmt.Sprintf("$IPT -t nat -A POSTROUTING -o \"$WG_IF\" -j MASQUERADE\n\n"))
		}
	}
	
	script.WriteString("echo \"[postup] Client interface $WG_IF configured\"\n")
	
	return script.String()
}

// generateClientPostDownScript generates a simplified PostDown script for client-type interfaces  
func generateClientPostDownScript(wgIf string, iface *model.WgInterface, allInterfaces []model.WgInterface) string {
	var script strings.Builder
	
	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -eu\n\n")
	script.WriteString(fmt.Sprintf("WG_IF=\"%s\"\n", wgIf))
	script.WriteString("IPT=\"$(command -v iptables || echo iptables)\"\n\n")
	
	script.WriteString("echo \"[postdown] Client interface $WG_IF shutting down\"\n\n")
	
	// Remove inter-interface routing rules if configured
	if iface != nil && len(iface.RemoteNetworks) > 0 {
		script.WriteString("# Remove inter-interface routing rules\n")

		// Remove SNAT if it was enabled
		if iface.EnableSNAT {
			script.WriteString(fmt.Sprintf("$IPT -t nat -D POSTROUTING -o \"$WG_IF\" -j MASQUERADE 2>/dev/null || true\n\n"))
		}

		// Remove traffic rules from other allowed interfaces
		if len(iface.AllowedInterfaces) > 0 {
			ifaceMap := make(map[string]string)
			for _, otherIface := range allInterfaces {
				ifaceMap[otherIface.ID] = otherIface.ID
			}

			for _, allowedIfaceID := range iface.AllowedInterfaces {
				if _, exists := ifaceMap[allowedIfaceID]; !exists {
					continue
				}

				for _, remoteNet := range iface.RemoteNetworks {
					script.WriteString(fmt.Sprintf("$IPT -D FORWARD -i %s -o \"$WG_IF\" -d %s -j ACCEPT 2>/dev/null || true\n", allowedIfaceID, remoteNet))
					script.WriteString(fmt.Sprintf("$IPT -D FORWARD -i \"$WG_IF\" -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true\n", allowedIfaceID))
				}
			}
		}

		// Remove LAN to remote networks rules
		for _, remoteNet := range iface.RemoteNetworks {
			script.WriteString(fmt.Sprintf("$IPT -D FORWARD -o \"$WG_IF\" -d %s -j ACCEPT 2>/dev/null || true\n", remoteNet))
			script.WriteString(fmt.Sprintf("$IPT -D FORWARD -i \"$WG_IF\" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true\n"))
		}
		script.WriteString("\n")
	}
	
	script.WriteString("echo \"[postdown] Client interface $WG_IF cleaned up\"\n")
	
	return script.String()
}

// GenerateAndSaveScripts generates and saves PostUp/PostDown scripts to disk
func GenerateAndSaveScripts(globalSettings model.GlobalSetting, server *model.Server, firewallRules []model.FirewallRule, clients []model.ClientData) error {
// Determine script paths - use configured paths or defaults
postUpPath := globalSettings.PostUpScriptPath
if postUpPath == "" {
// Use default path next to config file
configDir := ""
if globalSettings.ConfigFilePath != "" {
lastSlash := strings.LastIndex(globalSettings.ConfigFilePath, "/")
if lastSlash > 0 {
configDir = globalSettings.ConfigFilePath[:lastSlash]
}
}
if configDir == "" {
configDir = "/etc/wireguard"
}
postUpPath = configDir + "/postup.sh"
}

postDownPath := globalSettings.PostDownScriptPath
if postDownPath == "" {
// Use default path next to config file
configDir := ""
if globalSettings.ConfigFilePath != "" {
lastSlash := strings.LastIndex(globalSettings.ConfigFilePath, "/")
if lastSlash > 0 {
configDir = globalSettings.ConfigFilePath[:lastSlash]
}
}
if configDir == "" {
configDir = "/etc/wireguard"
}
postDownPath = configDir + "/postdown.sh"
}

// Calculate WG_SUBNETS from server interface addresses
wgSubnets := ""
if server != nil && server.Interface != nil && len(server.Interface.Addresses) > 0 {
	wgSubnets = strings.Join(server.Interface.Addresses, " ")
}

// Generate scripts
postUpScript := GeneratePostUpScript(globalSettings, wgSubnets, firewallRules, clients, "wg0")
postDownScript := GeneratePostDownScript(globalSettings, wgSubnets, firewallRules, clients, "wg0")

// Write PostUp script
err := os.WriteFile(postUpPath, []byte(postUpScript), 0755)
if err != nil {
return fmt.Errorf("failed to write PostUp script to %s: %v", postUpPath, err)
}

// Write PostDown script
err = os.WriteFile(postDownPath, []byte(postDownScript), 0755)
if err != nil {
return fmt.Errorf("failed to write PostDown script to %s: %v", postDownPath, err)
}

return nil
}
