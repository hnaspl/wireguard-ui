package handler

import (
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

// GetInterfaces returns list of all interfaces
func GetInterfaces(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		interfaces, err := db.GetInterfaces()
		if err != nil {
			log.Error("Cannot get interfaces from database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, "Cannot get interfaces from database",
			})
		}

		return c.JSON(http.StatusOK, interfaces)
	}
}

// GetInterface returns a specific interface by ID
func GetInterface(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		interfaceID := c.Param("id")

		iface, err := db.GetInterface(interfaceID)
		if err != nil {
			log.Error("Cannot get interface from database: ", err)
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{
				false, "Interface not found",
			})
		}

		return c.JSON(http.StatusOK, iface)
	}
}

// CreateInterface creates a new interface
func CreateInterface(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var iface model.WgInterface
		if err := c.Bind(&iface); err != nil {
			log.Error("Cannot decode interface JSON: ", err)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
				false, "Invalid interface data",
			})
		}

		// Validate required fields
		if iface.ID == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
				false, "Interface ID is required",
			})
		}

		if iface.Name == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
				false, "Interface name is required",
			})
		}

		if iface.Type == "" {
			iface.Type = model.WgInterfaceTypeServer
		}

		if iface.Type != model.WgInterfaceTypeServer && iface.Type != model.WgInterfaceTypeClient {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
				false, "Interface type must be 'server' or 'client'",
			})
		}

		// Set default Table to "off" for Docker compatibility if not provided
		if iface.Table == "" {
			iface.Table = "off"
		}

		// Check if interface already exists
		_, err := db.GetInterface(iface.ID)
		if err == nil {
			return c.JSON(http.StatusConflict, jsonHTTPResponse{
				false, "Interface with this ID already exists",
			})
		}

		// Generate private key if not provided
		if iface.PrivateKey == "" {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				log.Error("Cannot generate private key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
					false, "Cannot generate private key",
				})
			}
			iface.PrivateKey = key.String()
			iface.PublicKey = key.PublicKey().String()
		} else {
			// Validate and calculate public key from private key
			key, err := wgtypes.ParseKey(iface.PrivateKey)
			if err != nil {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
					false, "Invalid private key format",
				})
			}
			iface.PublicKey = key.PublicKey().String()
		}

		// Set default config file path if not provided
		if iface.ConfigFilePath == "" {
			iface.ConfigFilePath = "/etc/wireguard/" + iface.ID + ".conf"
		}

		// Set timestamps
		iface.Created = time.Now().UTC()
		iface.Updated = time.Now().UTC()

		// Save interface
		if err := db.SaveInterface(iface); err != nil {
			log.Error("Cannot save interface to database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, "Cannot save interface",
			})
		}

		return c.JSON(http.StatusCreated, iface)
	}
}

// UpdateInterface updates an existing interface
func UpdateInterface(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		interfaceID := c.Param("id")

		// Check if interface exists
		existingIface, err := db.GetInterface(interfaceID)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{
				false, "Interface not found",
			})
		}

		var iface model.WgInterface
		if err := c.Bind(&iface); err != nil {
			log.Error("Cannot decode interface JSON: ", err)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
				false, "Invalid interface data",
			})
		}

		// Ensure ID matches URL parameter
		iface.ID = interfaceID

		// Preserve creation time
		iface.Created = existingIface.Created

		// If private key changed, recalculate public key
		if iface.PrivateKey != "" && iface.PrivateKey != existingIface.PrivateKey {
			key, err := wgtypes.ParseKey(iface.PrivateKey)
			if err != nil {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
					false, "Invalid private key format",
				})
			}
			iface.PublicKey = key.PublicKey().String()
		} else if iface.PrivateKey == "" {
			// Preserve existing keys if not provided
			iface.PrivateKey = existingIface.PrivateKey
			iface.PublicKey = existingIface.PublicKey
		}

		// Update timestamp
		iface.Updated = time.Now().UTC()

		// Save interface
		if err := db.SaveInterface(iface); err != nil {
			log.Error("Cannot update interface in database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, "Cannot update interface",
			})
		}

		return c.JSON(http.StatusOK, iface)
	}
}

// DeleteInterface deletes an interface
func DeleteInterface(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		interfaceID := c.Param("id")

		// Check if interface exists
		iface, err := db.GetInterface(interfaceID)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{
				false, "Interface not found",
			})
		}

		// Don't allow deleting the default interface
		if iface.IsDefault {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
				false, "Cannot delete the default interface",
			})
		}

		// Check if there are clients using this interface
		clients, err := db.GetClientsByInterface(interfaceID, false)
		if err == nil && len(clients) > 0 {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
				false, "Cannot delete interface with existing clients. Please remove all clients first.",
			})
		}

		// Delete the interface
		if err := db.DeleteInterface(interfaceID); err != nil {
			log.Error("Cannot delete interface from database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, "Cannot delete interface",
			})
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{
			true, "Interface deleted successfully",
		})
	}
}

// ToggleInterface enables or disables an interface
func ToggleInterface(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		interfaceID := c.Param("id")

		iface, err := db.GetInterface(interfaceID)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{
				false, "Interface not found",
			})
		}

		// Toggle enabled status
		iface.Enabled = !iface.Enabled
		iface.Updated = time.Now().UTC()

		if err := db.SaveInterface(iface); err != nil {
			log.Error("Cannot update interface in database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, "Cannot toggle interface",
			})
		}

		return c.JSON(http.StatusOK, iface)
	}
}

// GetInterfaceClients returns all clients for a specific interface
func GetInterfaceClients(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		interfaceID := c.Param("id")

		// Check if interface exists
		_, err := db.GetInterface(interfaceID)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{
				false, "Interface not found",
			})
		}

		clients, err := db.GetClientsByInterface(interfaceID, true)
		if err != nil {
			log.Error("Cannot get clients for interface from database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, "Cannot get clients",
			})
		}

		return c.JSON(http.StatusOK, clients)
	}
}

// GetInterfaceFirewallRules returns all firewall rules for a specific interface
func GetInterfaceFirewallRules(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		interfaceID := c.Param("id")

		// Check if interface exists
		_, err := db.GetInterface(interfaceID)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{
				false, "Interface not found",
			})
		}

		rules, err := db.GetFirewallRulesByInterface(interfaceID)
		if err != nil {
			log.Error("Cannot get firewall rules for interface from database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, "Cannot get firewall rules",
			})
		}

		return c.JSON(http.StatusOK, rules)
	}
}

// InterfacesPage handler to show the interfaces management page
func InterfacesPage() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "interfaces.html", map[string]interface{}{
			"baseData": model.BaseData{Active: "interfaces", CurrentUser: currentUser(c), Admin: isAdmin(c)},
		})
	}
}

// ApplyInterfaceConfig applies configuration for a specific interface
func ApplyInterfaceConfig(db store.IStore, tmplDir fs.FS) echo.HandlerFunc {
	return func(c echo.Context) error {
		interfaceID := c.Param("id")

		// Check if interface exists
		_, err := db.GetInterface(interfaceID)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{
				false, "Interface not found",
			})
		}

		// Apply configuration for this interface
		if err := util.ApplyInterfaceConfig(db, tmplDir, interfaceID); err != nil {
			log.Error("Cannot apply interface config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot apply interface config: %v", err),
			})
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{
			true, "Applied configuration for interface " + interfaceID + " successfully",
		})
	}
}
