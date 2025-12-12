package jsondb

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GetInterfaces retrieves all interfaces from the database
func (o *JsonDB) GetInterfaces() ([]model.WgInterface, error) {
	var interfaces []model.WgInterface
	interfacesPath := path.Join(o.dbPath, "interfaces")
	
	// Create interfaces directory if it doesn't exist
	if _, err := os.Stat(interfacesPath); os.IsNotExist(err) {
		if err := os.MkdirAll(interfacesPath, os.ModePerm); err != nil {
			return interfaces, err
		}
	}
	
	results, err := o.conn.ReadAll("interfaces")
	if err != nil {
		// If no interfaces exist yet, return empty slice (not an error)
		return interfaces, nil
	}
	
	for _, data := range results {
		iface := model.WgInterface{}
		if err := json.Unmarshal(data, &iface); err != nil {
			return interfaces, fmt.Errorf("cannot decode interface json structure: %v", err)
		}
		interfaces = append(interfaces, iface)
	}
	
	return interfaces, nil
}

// GetInterface retrieves a specific interface by ID
func (o *JsonDB) GetInterface(id string) (model.WgInterface, error) {
	iface := model.WgInterface{}
	
	if err := o.conn.Read("interfaces", id, &iface); err != nil {
		return iface, err
	}
	
	return iface, nil
}

// SaveInterface saves an interface to the database
func (o *JsonDB) SaveInterface(iface model.WgInterface) error {
	// Calculate public key from private key if not set
	if iface.PrivateKey != "" && iface.PublicKey == "" {
		key, err := wgtypes.ParseKey(iface.PrivateKey)
		if err == nil {
			iface.PublicKey = key.PublicKey().String()
		}
	}
	
	// Set timestamps
	if iface.Created.IsZero() {
		iface.Created = time.Now().UTC()
	}
	iface.Updated = time.Now().UTC()
	
	interfacePath := path.Join(path.Join(o.dbPath, "interfaces"), iface.ID+".json")
	output := o.conn.Write("interfaces", iface.ID, iface)
	err := util.ManagePerms(interfacePath)
	if err != nil {
		return err
	}
	return output
}

// DeleteInterface removes an interface from the database
func (o *JsonDB) DeleteInterface(id string) error {
	return o.conn.Delete("interfaces", id)
}

// GetClientsByInterface retrieves all clients for a specific interface
func (o *JsonDB) GetClientsByInterface(interfaceID string, hasQRCode bool) ([]model.ClientData, error) {
	var clients []model.ClientData
	
	// Get all clients first
	allClients, err := o.GetClients(hasQRCode)
	if err != nil {
		return clients, err
	}
	
	// Filter by interface ID
	for _, clientData := range allClients {
		if clientData.Client != nil && clientData.Client.InterfaceID == interfaceID {
			clients = append(clients, clientData)
		}
	}
	
	return clients, nil
}

// GetFirewallRulesByInterface retrieves all firewall rules for a specific interface
func (o *JsonDB) GetFirewallRulesByInterface(interfaceID string) ([]model.FirewallRule, error) {
	var rules []model.FirewallRule
	
	// Get all firewall rules first
	allRules, err := o.GetFirewallRules()
	if err != nil {
		return rules, err
	}
	
	// Filter by interface ID
	for _, rule := range allRules {
		if rule.InterfaceID == interfaceID {
			rules = append(rules, rule)
		}
	}
	
	return rules, nil
}

// MigrateToMultiInterface creates a default wg0 interface from existing server configuration
// This function should be called during Init() if no interfaces exist
func (o *JsonDB) MigrateToMultiInterface() error {
	// Check if interfaces already exist
	interfaces, err := o.GetInterfaces()
	if err == nil && len(interfaces) > 0 {
		// Migration already done
		return nil
	}
	
	// Read existing server configuration
	server, err := o.GetServer()
	if err != nil {
		return fmt.Errorf("cannot read server configuration for migration: %v", err)
	}
	
	// Create default wg0 interface from server settings
	defaultInterface := model.WgInterface{
		ID:                 "wg0",
		Name:               "Default Server",
		Type:               model.WgInterfaceTypeServer,
		InterfaceAddresses: server.Interface.Addresses,
		PrivateKey:         server.KeyPair.PrivateKey,
		PublicKey:          server.KeyPair.PublicKey,
		ListenPort:         server.Interface.ListenPort,
		MTU:                0, // Will use global setting
		DNS:                []string{}, // Will use global setting
		PostUpScript:       server.Interface.PostUp,
		PostDownScript:     server.Interface.PostDown,
		ConfigFilePath:     util.LookupEnvOrString(util.ConfigFilePathEnvVar, util.DefaultConfigFilePath),
		Enabled:            true,
		IsDefault:          true,
		Created:            time.Now().UTC(),
		Updated:            time.Now().UTC(),
	}
	
	// Save the default interface
	if err := o.SaveInterface(defaultInterface); err != nil {
		return fmt.Errorf("cannot save default interface: %v", err)
	}
	
	// Update all existing clients to reference wg0
	clients, err := o.GetClients(false)
	if err != nil {
		return fmt.Errorf("cannot read clients for migration: %v", err)
	}
	
	for _, clientData := range clients {
		if clientData.Client != nil {
			client := *clientData.Client
			// Only update if InterfaceID is not set (backward compatibility)
			if client.InterfaceID == "" {
				client.InterfaceID = "wg0"
				if err := o.SaveClient(client); err != nil {
					return fmt.Errorf("cannot update client %s: %v", client.ID, err)
				}
			}
		}
	}
	
	// Update all existing firewall rules to reference wg0
	rules, err := o.GetFirewallRules()
	if err != nil {
		return fmt.Errorf("cannot read firewall rules for migration: %v", err)
	}
	
	for _, rule := range rules {
		// Only update if InterfaceID is not set (backward compatibility)
		if rule.InterfaceID == "" {
			rule.InterfaceID = "wg0"
			if err := o.SaveFirewallRule(rule); err != nil {
				return fmt.Errorf("cannot update firewall rule %s: %v", rule.ID, err)
			}
		}
	}
	
	return nil
}
