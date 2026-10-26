// Package decisions maintains the local CrowdSec decision cache used by the
// stream bouncer.
package decisions

import (
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gaissmai/bart"
)

// Cache applies decision stream updates and offers lock-free IP lookups.
// CrowdSec sends deleted decisions as well as new decisions, so the cache can
// retain its last known-good state while a later stream update temporarily
// fails.
type Cache struct {
	// mu serializes writers; readers never take it.
	mu sync.Mutex
	decisions map[int64]*models.Decision
	// atomic pointer to the current trie for lock-free reads
	triePtr atomic.Pointer[bart.Table[*models.Decision]]
}

func NewCache() *Cache {
	c := &Cache{decisions: make(map[int64]*models.Decision)}
	c.triePtr.Store(new(bart.Table[*models.Decision]))
	return c
}

func prefixFromDecision(decision *models.Decision) (netip.Prefix, bool) {
	if decision == nil || decision.Value == nil || decision.Scope == nil {
		return netip.Prefix{}, false
	}
	if ip, err := netip.ParseAddr(*decision.Value); err == nil && strings.EqualFold(*decision.Scope, "ip") {
		return netip.PrefixFrom(ip, ip.BitLen()), true
	}
	prefix, err := netip.ParsePrefix(*decision.Value)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

// Apply updates the cache with one response from /v1/decisions/stream.
func (c *Cache) Apply(update *models.DecisionsStreamResponse) {
	if update == nil || (len(update.New) == 0 && len(update.Deleted) == 0) {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	next := c.triePtr.Load().Clone() // copy-on-write

	for _, decision := range update.Deleted {
		if decision != nil {
			// Remove the decision from the map
			delete(c.decisions, decision.ID)
			// and from the prefix trie
			prefix, ok := prefixFromDecision(decision)
			if !ok {
				continue
			}
			next.Delete(prefix)
		}
	}

	for _, decision := range update.New {
		if decision == nil || decision.Type == nil || !strings.EqualFold(*decision.Type, "ban") {
			continue
		}
		c.decisions[decision.ID] = decision
		// Add the decision to the prefix trie
		prefix, ok := prefixFromDecision(decision)
		if !ok {
			continue
		}
		next.Insert(prefix, decision)
	}
	c.triePtr.Store(next)
}

// GetBan returns the most specific matching IP or CIDR ban decision, if any.
func (c *Cache) GetBan(rawIP string) *models.Decision {
	ip, err := netip.ParseAddr(rawIP)
	if err != nil {
		return nil
	}

	decision, present := c.triePtr.Load().Lookup(ip)
	if present {
		return decision
	}
	return nil
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
