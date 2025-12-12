package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/rs/xid"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
)

// FirewallRules handler for the firewall rules management page
func FirewallRules(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "firewall_rules.html", map[string]interface{}{
			"baseData": model.BaseData{Active: "firewall-rules", CurrentUser: currentUser(c), Admin: isAdmin(c)},
		})
	}
}

// GetFirewallRules API handler to get all firewall rules
func GetFirewallRules(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		rules, err := db.GetFirewallRules()
		if err != nil {
			log.Error("Cannot get firewall rules: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get firewall rules"})
		}

		// Enrich with client names
		clients, err := db.GetClients(false)
		if err == nil {
			clientMap := make(map[string]string)
			for _, clientData := range clients {
				if clientData.Client != nil {
					clientMap[clientData.Client.ID] = clientData.Client.Name
				}
			}
			for i := range rules {
				if name, ok := clientMap[rules[i].ClientID]; ok {
					rules[i].ClientName = name
				}
			}
		}

		return c.JSON(http.StatusOK, rules)
	}
}

// GetFirewallRule API handler to get a single firewall rule
func GetFirewallRule(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		ruleID := c.Param("id")
		if ruleID == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Rule ID is required"})
		}

		rule, err := db.GetFirewallRule(ruleID)
		if err != nil {
			log.Errorf("Cannot get firewall rule %s: %v", ruleID, err)
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Rule not found"})
		}

		return c.JSON(http.StatusOK, rule)
	}
}

// SaveFirewallRule API handler to create a new firewall rule
func SaveFirewallRule(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var rule model.FirewallRule
		err := json.NewDecoder(c.Request().Body).Decode(&rule)
		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid request data"})
		}

		// Validate required fields
		if rule.ClientID == "" || rule.AllowedIP == "" || rule.AllowedPort == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Client ID, allowed IP, and port are required"})
		}

		// Assign to interface based on client's interface if not specified
		if rule.InterfaceID == "" {
			// Get the client to find their interface
			client, err := db.GetClientByID(rule.ClientID, model.QRCodeSettings{Enabled: false})
			if err == nil && client.Client != nil && client.Client.InterfaceID != "" {
				rule.InterfaceID = client.Client.InterfaceID
			} else {
				// Fallback to default interface
				interfaces, err := db.GetInterfaces()
				if err == nil && len(interfaces) > 0 {
					for _, iface := range interfaces {
						if iface.IsDefault {
							rule.InterfaceID = iface.ID
							break
						}
					}
					if rule.InterfaceID == "" {
						rule.InterfaceID = interfaces[0].ID
					}
				} else {
					rule.InterfaceID = "wg0"
				}
			}
		}

		// Generate ID for new rule
		rule.ID = xid.New().String()
		rule.CreatedAt = time.Now().UTC()
		rule.UpdatedAt = time.Now().UTC()

		if err := db.SaveFirewallRule(rule); err != nil {
			log.Errorf("Cannot save firewall rule: %v", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot save firewall rule"})
		}

		log.Infof("Created firewall rule: %v", rule)
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Firewall rule created successfully"})
	}
}

// UpdateFirewallRule API handler to update an existing firewall rule
func UpdateFirewallRule(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		ruleID := c.Param("id")
		if ruleID == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Rule ID is required"})
		}

		var rule model.FirewallRule
		err := json.NewDecoder(c.Request().Body).Decode(&rule)
		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid request data"})
		}

		// Validate required fields
		if rule.ClientID == "" || rule.AllowedIP == "" || rule.AllowedPort == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Client ID, allowed IP, and port are required"})
		}

		// Get existing rule to preserve created_at
		existingRule, err := db.GetFirewallRule(ruleID)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Rule not found"})
		}

		rule.ID = ruleID
		rule.CreatedAt = existingRule.CreatedAt
		rule.UpdatedAt = time.Now().UTC()

		if err := db.SaveFirewallRule(rule); err != nil {
			log.Errorf("Cannot update firewall rule: %v", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot update firewall rule"})
		}

		log.Infof("Updated firewall rule: %v", rule)
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Firewall rule updated successfully"})
	}
}

// DeleteFirewallRule API handler to delete a firewall rule
func DeleteFirewallRule(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		ruleID := c.Param("id")
		if ruleID == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Rule ID is required"})
		}

		if err := db.DeleteFirewallRule(ruleID); err != nil {
			log.Errorf("Cannot delete firewall rule %s: %v", ruleID, err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot delete firewall rule"})
		}

		log.Infof("Deleted firewall rule: %s", ruleID)
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Firewall rule deleted successfully"})
	}
}
