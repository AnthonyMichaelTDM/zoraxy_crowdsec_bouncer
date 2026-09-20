package decisions

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func BenchmarkLargeBlocklist(b *testing.B) {
	c := NewCache()
	update := &models.DecisionsStreamResponse{}
	for i := 0; i < 100000; i++ {
		update.New = append(update.New, decision(int64(i), "ip", fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255), "ban"))
	}
	c.Apply(update)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if c.GetBan("192.0.2.123") != nil {
			b.Fatal("unexpected ban")
		}
	}
}

func TestIndexPreservesDecisionMatching(t *testing.T) {
	c := NewCache()
	ds := []*models.Decision{
		decision(1, "range", "203.0.113.9/24", "ban"),
		decision(2, "range", "203.0.113.10/32", "ban"),
		decision(3, "Ip", "203.0.113.10", "ban"),
		decision(4, "ip", "203.0.113.10/32", "ban"),
		decision(5, "range", "2001:db8::/32", "ban"),
		decision(6, "ip", "2001:db8::42", "ban"),
		decision(7, "range", "0.0.0.0/0", "ban"),
		decision(8, "ip", "invalid", "ban"),
	}
	c.Apply(&models.DecisionsStreamResponse{New: ds})
	check := func() {
		t.Helper()
		for _, raw := range []string{"203.0.113.10", "203.0.113.11", "192.0.2.1", "2001:db8::42", "2001:db8::43", "2001:db9::1"} {
			ip := netip.MustParseAddr(raw)
			var want *models.Decision
			best := -1
			for _, d := range c.decisions {
				specificity, match := decisionMatchSpecificity(d, ip)
				if match && (want == nil || specificity > best || (specificity == best && d.ID > want.ID)) {
					want = d
					best = specificity
				}
			}
			if got := c.GetBan(raw); got != want {
				t.Fatalf("%s: got %v want %v", raw, got, want)
			}
		}
	}
	check()
	for _, d := range ds {
		c.Apply(&models.DecisionsStreamResponse{Deleted: []*models.Decision{d}})
		check()
	}
}
