//go:build !linux

package babel

import log "github.com/sirupsen/logrus"

// defaultRuleInstaller is a no-op on non-Linux platforms: babeld and its kernel
// policy-routing integration are Linux-only. Mesh links can still carry traffic
// via their WireGuard interfaces; only the dynamic Babel-table steering is absent.
func defaultRuleInstaller() RuleInstaller {
	return noopRuleInstaller{}
}

type noopRuleInstaller struct{}

func (noopRuleInstaller) Install(spec RuleSpec) error {
	log.Debugf("babel: route-rule install is a no-op on this platform (%+v)", spec)
	return nil
}

func (noopRuleInstaller) Remove(RuleSpec) error { return nil }
