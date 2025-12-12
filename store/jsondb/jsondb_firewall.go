package jsondb

import (
	"encoding/json"

	"github.com/ngoduykhanh/wireguard-ui/model"
)

// GetFirewallRules get all firewall rules
func (o *JsonDB) GetFirewallRules() ([]model.FirewallRule, error) {
	var rules []model.FirewallRule

	records, err := o.conn.ReadAll("firewall_rules")
	if err != nil {
		// If no firewall rules exist yet (collection not found or empty), return empty slice
		// This is not an error condition - just means no rules are configured yet
		return rules, nil
	}

	for _, f := range records {
		rule := model.FirewallRule{}
		if err := json.Unmarshal(f, &rule); err != nil {
			return rules, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// GetFirewallRule get firewall rule by ID
func (o *JsonDB) GetFirewallRule(id string) (model.FirewallRule, error) {
	rule := model.FirewallRule{}

	if err := o.conn.Read("firewall_rules", id, &rule); err != nil {
		return rule, err
	}

	return rule, nil
}

// SaveFirewallRule save firewall rule to database
func (o *JsonDB) SaveFirewallRule(rule model.FirewallRule) error {
	return o.conn.Write("firewall_rules", rule.ID, rule)
}

// DeleteFirewallRule remove firewall rule from database
func (o *JsonDB) DeleteFirewallRule(id string) error {
	return o.conn.Delete("firewall_rules", id)
}
