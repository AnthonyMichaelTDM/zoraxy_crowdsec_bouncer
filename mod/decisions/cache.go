// Package decisions maintains the local CrowdSec decision cache used by the
// stream bouncer.
package decisions

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gaissmai/bart"
)

// entry is the trie value for one prefix.
type entry struct {
	best *models.Decision
	// others holds the remaining decisions at the prefix, so the next-best one
	// can be promoted when the winner is removed. It is nil in the common case
	// of a single decision.
	others []*models.Decision
}

// Cache applies decision stream updates and offers concurrent-safe IP lookups.
// CrowdSec sends deleted decisions as well as new decisions, so the cache can
// retain its last known-good state while a later stream update temporarily
// fails.
type Cache struct {
	// mu guards decisions and trie. Updates edit the trie in place under the
	// write lock, so lookups block while an update is being applied.
	mu sync.RWMutex
	// decisions maps decision IDs to decisions, so a deleted or replaced ID
	// can be removed from the prefix it was originally indexed under.
	decisions map[int64]*models.Decision
	trie      bart.Table[entry]
}

func NewCache() *Cache {
	return &Cache{decisions: make(map[int64]*models.Decision)}
}

func prefixFromDecision(decision *models.Decision) (netip.Prefix, bool) {
	if decision == nil || decision.Value == nil || decision.Scope == nil {
		return netip.Prefix{}, false
	}
	scope := strings.ToLower(*decision.Scope)
	if scope != "ip" && scope != "range" {
		return netip.Prefix{}, false
	}
	if ip, err := netip.ParseAddr(*decision.Value); err == nil && scope == "ip" {
		return netip.PrefixFrom(ip, ip.BitLen()), true
	}
	prefix, err := netip.ParsePrefix(*decision.Value)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

// better reports whether a should win over b at the same prefix: higher
// specificity first, then higher ID.
func better(a, b *models.Decision, addr netip.Addr) bool {
	aSpec, _ := decisionMatchSpecificity(a, addr)
	bSpec, _ := decisionMatchSpecificity(b, addr)
	return aSpec > bSpec || (aSpec == bSpec && a.ID > b.ID)
}

// without returns a copy of list with the decision of the given ID removed.
func without(list []*models.Decision, id int64) []*models.Decision {
	var out []*models.Decision = make([]*models.Decision, 0, len(list))
	for _, d := range list {
		if d.ID != id {
			out = append(out, d)
		}
	}
	return out
}

// unindex removes the decision from its prefix in the trie.
func (c *Cache) unindex(decision *models.Decision) {
	prefix, ok := prefixFromDecision(decision)
	if !ok {
		return
	}
	c.trie.Modify(prefix, func(old entry, found bool) (entry, bool) {
		if !found {
			return entry{}, true
		}
		if old.best.ID != decision.ID {
			return entry{best: old.best, others: without(old.others, decision.ID)}, false
		}
		if len(old.others) == 0 {
			return entry{}, true
		}
		best := old.others[0]
		for _, d := range old.others[1:] {
			if better(d, best, prefix.Addr()) {
				best = d
			}
		}
		return entry{best: best, others: without(old.others, best.ID)}, false
	})
}

// index adds the decision to its prefix in the trie.
func (c *Cache) index(decision *models.Decision) {
	prefix, ok := prefixFromDecision(decision)
	if !ok {
		return
	}
	c.trie.Modify(prefix, func(old entry, found bool) (entry, bool) {
		if !found {
			return entry{best: decision}, false
		}
		winner, loser := old.best, decision
		if better(decision, old.best, prefix.Addr()) {
			winner, loser = decision, old.best
		}
		return entry{best: winner, others: append(old.others, loser)}, false
	})
}

// Apply updates the cache with one response from /v1/decisions/stream.
func (c *Cache) Apply(update *models.DecisionsStreamResponse) {
	if update == nil || (len(update.New) == 0 && len(update.Deleted) == 0) {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, decision := range update.Deleted {
		if decision == nil {
			continue
		}
		if existing, ok := c.decisions[decision.ID]; ok {
			c.unindex(existing)
			delete(c.decisions, decision.ID)
		}
	}

	for _, decision := range update.New {
		if decision == nil || decision.Type == nil || !strings.EqualFold(*decision.Type, "ban") {
			continue
		}
		if existing, ok := c.decisions[decision.ID]; ok {
			c.unindex(existing)
		}
		c.decisions[decision.ID] = decision
		c.index(decision)
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
	if e, ok := c.trie.Lookup(ip); ok {
		return e.best
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
