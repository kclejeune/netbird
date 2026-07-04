package babel

import (
	log "github.com/sirupsen/logrus"
)

// Address families for RuleSpec (kept netlink-independent so this file builds on
// every platform; the Linux installer maps them to netlink families).
const (
	FamilyV4 = 4
	FamilyV6 = 6
)

// DefaultRulePriority is the ip-rule priority for the Babel-table steering rule.
// It sits between NetBird's main-suppress rule (105) and its VPN-table rule
// (110): mesh-destined packets consult Babel's table first, and a table miss
// falls through to NetBird's rules, so non-mesh traffic is unaffected.
const DefaultRulePriority = 108

// RuleSpec describes a policy-routing rule steering a destination prefix to a
// routing table. It is the platform-neutral description; RuleInstaller applies it.
type RuleSpec struct {
	Priority int
	Family   int
	Dst      string // CIDR, e.g. "100.64.0.0/10"
	Table    int
}

// RuleInstaller applies/removes policy-routing rules. The Linux implementation
// uses netlink; other platforms use a no-op. Tests inject a fake.
type RuleInstaller interface {
	Install(RuleSpec) error
	Remove(RuleSpec) error
}

// RouteRuleSpecs returns the rules that make babeld's exported routes take
// effect: without a rule directing lookups to the export table, the routes
// babeld installs there are never consulted. The mesh prefix is IPv4
// (NetBird's CGNAT range), so a single v4 rule is emitted.
func (m *Manager) RouteRuleSpecs() []RuleSpec {
	return []RuleSpec{{
		Priority: DefaultRulePriority,
		Family:   FamilyV4,
		Dst:      m.config.MeshPrefix,
		Table:    m.config.ExportTable,
	}}
}

// SetRuleInstaller overrides the rule installer (for tests).
func (m *Manager) SetRuleInstaller(ri RuleInstaller) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ruleInstaller = ri
}

// installRouteRulesLocked installs the steering rules (best-effort). Caller holds m.mu.
func (m *Manager) installRouteRulesLocked() {
	if m.config.DisableKernelRules || m.ruleInstaller == nil {
		return
	}
	m.installedRules = m.installedRules[:0]
	for _, spec := range m.RouteRuleSpecs() {
		if err := m.ruleInstaller.Install(spec); err != nil {
			log.Warnf("babel: install route rule %+v: %v", spec, err)
			continue
		}
		m.installedRules = append(m.installedRules, spec)
		log.Infof("babel: steering %s to table %d (priority %d)", spec.Dst, spec.Table, spec.Priority)
	}
}

// removeRouteRulesLocked removes previously-installed steering rules. Caller holds m.mu.
func (m *Manager) removeRouteRulesLocked() {
	if m.ruleInstaller == nil {
		return
	}
	for _, spec := range m.installedRules {
		if err := m.ruleInstaller.Remove(spec); err != nil {
			log.Warnf("babel: remove route rule %+v: %v", spec, err)
		}
	}
	m.installedRules = nil
}
