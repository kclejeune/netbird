//go:build linux

package babel

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// defaultRuleInstaller returns the Linux netlink-backed installer.
func defaultRuleInstaller() RuleInstaller {
	return netlinkRuleInstaller{}
}

type netlinkRuleInstaller struct{}

func (netlinkRuleInstaller) Install(spec RuleSpec) error {
	rule, err := toNetlinkRule(spec)
	if err != nil {
		return err
	}
	if err := netlink.RuleAdd(rule); err != nil {
		// EEXIST is fine (idempotent).
		if !isExist(err) {
			return fmt.Errorf("rule add: %w", err)
		}
	}
	return nil
}

func (netlinkRuleInstaller) Remove(spec RuleSpec) error {
	rule, err := toNetlinkRule(spec)
	if err != nil {
		return err
	}
	if err := netlink.RuleDel(rule); err != nil {
		if !isNotExist(err) {
			return fmt.Errorf("rule del: %w", err)
		}
	}
	return nil
}

func toNetlinkRule(spec RuleSpec) (*netlink.Rule, error) {
	_, dst, err := net.ParseCIDR(spec.Dst)
	if err != nil {
		return nil, fmt.Errorf("parse dst %q: %w", spec.Dst, err)
	}
	rule := netlink.NewRule()
	rule.Priority = spec.Priority
	rule.Table = spec.Table
	rule.Dst = dst
	switch spec.Family {
	case FamilyV6:
		rule.Family = netlink.FAMILY_V6
	default:
		rule.Family = netlink.FAMILY_V4
	}
	return rule, nil
}

func isExist(err error) bool {
	return err != nil && (err.Error() == "file exists" || errno(err) == 17) // EEXIST
}

func isNotExist(err error) bool {
	return err != nil && (err.Error() == "no such file or directory" || errno(err) == 2) // ENOENT
}

func errno(err error) int {
	type errnoer interface{ Errno() uintptr }
	if e, ok := err.(errnoer); ok {
		return int(e.Errno())
	}
	return -1
}
