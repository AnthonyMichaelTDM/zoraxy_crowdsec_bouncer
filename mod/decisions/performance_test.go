package decisions

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func largeBlocklistCache() *Cache {
	c := NewCache()
	update := &models.DecisionsStreamResponse{New: make([]*models.Decision, 0, 100001)}
	for i := range 100000 {
		update.New = append(update.New, decision(int64(i), "ip", fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255), "ban"))
	}
	update.New = append(update.New, decision(100000, "range", "192.0.2.0/24", "ban"))
	c.Apply(update)
	return c
}

func BenchmarkLargeBlocklistExactIPHit(b *testing.B) {
	c := largeBlocklistCache()
	b.ResetTimer()
	for b.Loop() {
		if c.GetBan("10.0.0.1") == nil {
			b.Fatal("expected exact-IP ban")
		}
	}
}

func BenchmarkLargeBlocklistCIDRHit(b *testing.B) {
	c := largeBlocklistCache()
	b.ResetTimer()
	for b.Loop() {
		if c.GetBan("192.0.2.123") == nil {
			b.Fatal("expected CIDR ban")
		}
	}
}

func BenchmarkLargeBlocklistIPv4Miss(b *testing.B) {
	c := largeBlocklistCache()
	b.ResetTimer()
	for b.Loop() {
		if c.GetBan("198.51.100.1") != nil {
			b.Fatal("unexpected ban")
		}
	}
}

func BenchmarkLargeBlocklistIPv6Miss(b *testing.B) {
	c := largeBlocklistCache()
	b.ResetTimer()
	for b.Loop() {
		if c.GetBan("2001:db8:ffff::1") != nil {
			b.Fatal("unexpected ban")
		}
	}
}

func BenchmarkUpdateLargeBlocklist(b *testing.B) {
	c := largeBlocklistCache()
	update := &models.DecisionsStreamResponse{New: make([]*models.Decision, 0, 1000)}
	for i := range 10000 {
		update.New = append(update.New, decision(int64(i), "ip", fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255), "ban"))
	}
	b.ResetTimer()
	for b.Loop() {
		c.Apply(update)
	}
}

func BenchmarkUpdateSmallBlocklist(b *testing.B) {
	c := NewCache()
	update := &models.DecisionsStreamResponse{New: make([]*models.Decision, 0, 100)}
	for i := range 100 {
		update.New = append(update.New, decision(int64(i), "ip", fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255), "ban"))
	}
	b.ResetTimer()
	for b.Loop() {
		c.Apply(update)
	}
}

// BenchmarkUpdateSteadyState applies many small deltas to an already large
// cache. Each update adds a batch of new decisions and deletes the previous
// batch, so the cache size stays constant.
func BenchmarkUpdateSteadyState(b *testing.B) {
	for _, batchSize := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("batch=%d", batchSize), func(b *testing.B) {
			c := largeBlocklistCache()

			const batches = 512
			pool := make([][]*models.Decision, batches)
			id := int64(1_000_000)
			for i := range pool {
				pool[i] = make([]*models.Decision, batchSize)
				for j := range pool[i] {
					// 172.16.0.0/12 doesn't overlap the 10.x.x.x base blocklist.
					n := int(id - 1_000_000)
					pool[i][j] = decision(id, "ip", fmt.Sprintf("172.%d.%d.%d", 16+(n>>16)&15, (n>>8)&255, n&255), "ban")
					id++
				}
			}

			b.ResetTimer()
			i := 0
			for b.Loop() {
				c.Apply(&models.DecisionsStreamResponse{
					New:     pool[i%batches],
					Deleted: pool[(i+batches-1)%batches],
				})
				i++
			}
		})
	}
}

func BenchmarkUpdateGrowingBlocklist(b *testing.B) {
	c := NewCache()
	i := 0
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		update := &models.DecisionsStreamResponse{New: make([]*models.Decision, 0, 1000)}
		for j := 0; j < 1000; j++ {
			update.New = append(update.New, decision(int64(i), "ip", fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255), "ban"))
			i++
		}
		b.StartTimer()
		c.Apply(update)
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
				t.Fatalf("%s: got %v want %v", raw, *got, *want)
			}
		}
	}
	check()
	for _, d := range ds {
		c.Apply(&models.DecisionsStreamResponse{Deleted: []*models.Decision{d}})
		check()
	}
}
