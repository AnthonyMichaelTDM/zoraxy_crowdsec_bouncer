// Package decisions maintains the local CrowdSec decision cache used by the
// stream bouncer.
package decisions

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// Cache applies decision stream updates and offers lock-safe IP lookups.
// CrowdSec sends deleted decisions as well as new decisions, so the cache can
// retain its last known-good state while a later stream update temporarily
// fails.
type Cache struct {
	mu        sync.RWMutex
	decisions map[int64]*models.Decision
}

func NewCache() *Cache {
	return &Cache{decisions: make(map[int64]*models.Decision)}
}

// Apply updates the cache with one response from /v1/decisions/stream.
func (c *Cache) Apply(update *models.DecisionsStreamResponse) {
	if update == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, decision := range update.Deleted {
		if decision != nil {
			delete(c.decisions, decision.ID)
		}
	}

	for _, decision := range update.New {
		if decision == nil || decision.Type == nil || !strings.EqualFold(*decision.Type, "ban") {
			continue
		}
		c.decisions[decision.ID] = decision
	}
}

// GetBan returns the most specific matching IP or CIDR ban decision, if any.
func (c *Cache) GetBan(rawIP string) *models.Decision {
	ip, err := netip.ParseAddr(rawIP)
	if err != nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var best *models.Decision
	bestSpecificity := -1
	for _, decision := range c.decisions {
		specificity, matches := decisionMatchSpecificity(decision, ip)
		if !matches {
			continue
		}
		if best == nil || specificity > bestSpecificity || (specificity == bestSpecificity && decision.ID > best.ID) {
			best = decision
			bestSpecificity = specificity
		}
	}

	return best
}

func decisionMatchSpecificity(decision *models.Decision, ip netip.Addr) (int, bool) {
	if decision == nil || decision.Scope == nil || decision.Value == nil {
		return 0, false
	}

	switch strings.ToLower(*decision.Scope) {
	case "ip":
		decisionIP, err := netip.ParseAddr(*decision.Value)
		if err == nil {
			return decisionIP.BitLen() + 1, decisionIP == ip
		}
		// CAPI decisions may be represented as an IP scope with a /32 or
		// /128 suffix, so accept a valid prefix here as well.
		prefix, err := netip.ParsePrefix(*decision.Value)
		if err != nil || !prefix.Contains(ip) {
			return 0, false
		}
		if prefix.Bits() == ip.BitLen() {
			return prefix.Bits() + 1, true
		}
		return prefix.Bits(), true
	case "range":
		prefix, err := netip.ParsePrefix(*decision.Value)
		if err != nil || !prefix.Contains(ip) {
			return 0, false
		}
		return prefix.Bits(), true
	default:
		return 0, false
	}
}
