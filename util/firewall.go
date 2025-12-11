package util

import (
	"fmt"
	"os"
	"strings"

	"github.com/ngoduykhanh/wireguard-ui/model"
)

// GenerateFirewallRules generates iptables commands from UI firewall rules
// These are inserted AFTER established/related and protected IP rules
func GenerateFirewallRules(firewallRules []model.FirewallRule, clients []model.ClientData, action string) string {
	if len(firewallRules) == 0 {
		return ""
	}

	var rules []string
	clientIPMap := make(map[string][]string)

	// Build map of client ID to their allocated IPs
	for _, clientData := range clients {
		if clientData.Client != nil && clientData.Client.Enabled {
			clientIPMap[clientData.Client.ID] = clientData.Client.AllocatedIPs
		}
	}

	// Generate rules for each firewall rule
	for _, rule := range firewallRules {
		if !rule.Enabled {
			continue
		}

		clientIPs, exists := clientIPMap[rule.ClientID]
		if !exists || len(clientIPs) == 0 {
			continue
		}

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
					ruleCmd += fmt.Sprintf(" --dport %s", rule.AllowedPort)
				}
			}

			ruleCmd += " -m conntrack --ctstate NEW -j ACCEPT"

			rules = append(rules, ruleCmd)
		}
	}

	// Add check to avoid duplicates when using -I (insert) mode
	var rulesWithChecks []string
	for _, rule := range rules {
		if action == "add" {
			// Replace -I with -C for check, then add the rule only if check fails
			checkRule := strings.Replace(rule, "$IPT -I FORWARD 1", "$IPT -C FORWARD", 1)
			safeRule := fmt.Sprintf("%s 2>/dev/null || \\\n%s", checkRule, rule)
			rulesWithChecks = append(rulesWithChecks, safeRule)
		} else {
			// For delete, add || true to ignore errors if rule doesn't exist
			rulesWithChecks = append(rulesWithChecks, rule+" 2>/dev/null || true")
		}
	}

	return strings.Join(rulesWithChecks, "\n")
}

// GeneratePostUpScript generates a complete PostUp script matching the user's pattern
func GeneratePostUpScript(globalSettings model.GlobalSetting, firewallRules []model.FirewallRule, clients []model.ClientData, interfaceName string) string {
	var script strings.Builder

	// Start with environment variable setup (matching user's pattern)
	wgIf := interfaceName
	if wgIf == "" {
		wgIf = "${INTERFACE:-wg0}"
	}

	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -eu\n\n")
	script.WriteString(fmt.Sprintf("WG_IF=\"%s\"\n", wgIf))
	
	// Set defaults matching user's script
	wgSubnets := globalSettings.WgSubnets
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
		iptablesRules := GenerateFirewallRules(firewallRules, clients, "add")
		if iptablesRules != "" {
			script.WriteString(iptablesRules)
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
func GeneratePostDownScript(globalSettings model.GlobalSetting, firewallRules []model.FirewallRule, clients []model.ClientData, interfaceName string) string {
	var script strings.Builder

	wgIf := interfaceName
	if wgIf == "" {
		wgIf = "${INTERFACE:-wg0}"
	}

	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -eu\n\n")
	script.WriteString(fmt.Sprintf("WG_IF=\"%s\"\n", wgIf))
	
	// Set defaults matching user's script
	wgSubnets := globalSettings.WgSubnets
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
		iptablesRules := GenerateFirewallRules(firewallRules, clients, "delete")
		if iptablesRules != "" {
			script.WriteString(iptablesRules)
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

// GenerateAndSaveScripts generates and saves PostUp/PostDown scripts to disk
func GenerateAndSaveScripts(globalSettings model.GlobalSetting, firewallRules []model.FirewallRule, clients []model.ClientData) error {
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

// Generate scripts
postUpScript := GeneratePostUpScript(globalSettings, firewallRules, clients, "wg0")
postDownScript := GeneratePostDownScript(globalSettings, firewallRules, clients, "wg0")

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
