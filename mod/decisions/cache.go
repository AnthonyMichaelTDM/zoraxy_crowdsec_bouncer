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

// entry is the immutable trie value for one prefix. Old tries share entries
// with new ones, so an entry and its slice must never be modified after being
// stored.
type entry struct {
	best *models.Decision
	// others holds the remaining decisions at the prefix, so the next-best one
	// can be promoted when the winner is removed. It is nil in the common case
	// of a single decision.
	others []*models.Decision
}

// Cache applies decision stream updates and offers lock-free IP lookups.
// CrowdSec sends deleted decisions as well as new decisions, so the cache can
// retain its last known-good state while a later stream update temporarily
// fails.
type Cache struct {
	// mu serializes writers; readers never take it.
	mu sync.Mutex
	// decisions maps decision IDs to decisions, so a deleted or replaced ID
	// can be removed from the prefix it was originally indexed under.
	decisions map[int64]*models.Decision
	// triePtr is the current trie; readers load it atomically.
	triePtr atomic.Pointer[bart.Table[entry]]
}

func NewCache() *Cache {
	c := &Cache{decisions: make(map[int64]*models.Decision)}
	c.triePtr.Store(new(bart.Table[entry]))
	return c
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
	var out []*models.Decision
	for _, d := range list {
		if d.ID != id {
			out = append(out, d)
		}
	}
	return out
}

// unindex removes the decision from its prefix in the trie.
func unindex(trie *bart.Table[entry], decision *models.Decision) {
	prefix, ok := prefixFromDecision(decision)
	if !ok {
		return
	}
	trie.Modify(prefix, func(old entry, found bool) (entry, bool) {
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
func index(trie *bart.Table[entry], decision *models.Decision) {
	prefix, ok := prefixFromDecision(decision)
	if !ok {
		return
	}
	trie.Modify(prefix, func(old entry, found bool) (entry, bool) {
		if !found {
			return entry{best: decision}, false
		}
		winner, loser := old.best, decision
		if better(decision, old.best, prefix.Addr()) {
			winner, loser = decision, old.best
		}
		others := make([]*models.Decision, 0, len(old.others)+1)
		others = append(others, old.others...)
		others = append(others, loser)
		return entry{best: winner, others: others}, false
	})
}

// Apply updates the cache with one response from /v1/decisions/stream.
func (c *Cache) Apply(update *models.DecisionsStreamResponse) {
	if update == nil || (len(update.New) == 0 && len(update.Deleted) == 0) {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// One clone per update is far cheaper than persistent per-decision updates.
	next := c.triePtr.Load().Clone()

	for _, decision := range update.Deleted {
		if decision == nil {
			continue
		}
		if existing, ok := c.decisions[decision.ID]; ok {
			unindex(next, existing)
			delete(c.decisions, decision.ID)
		}
	}

	for _, decision := range update.New {
		if decision == nil || decision.Type == nil || !strings.EqualFold(*decision.Type, "ban") {
			continue
		}
		if existing, ok := c.decisions[decision.ID]; ok {
			unindex(next, existing)
		}
		c.decisions[decision.ID] = decision
		index(next, decision)
	}
	c.triePtr.Store(next)
}

// GetBan returns the most specific matching IP or CIDR ban decision, if any.
func (c *Cache) GetBan(rawIP string) *models.Decision {
	ip, err := netip.ParseAddr(rawIP)
	if err != nil {
		return nil
	}

	if e, ok := c.triePtr.Load().Lookup(ip); ok {
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
