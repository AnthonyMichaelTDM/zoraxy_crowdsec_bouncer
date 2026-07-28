package decisions

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func str(value string) *string { return &value }

func decision(id int64, scope, value, decisionType string) *models.Decision {
	return &models.Decision{ID: id, Scope: str(scope), Value: str(value), Type: str(decisionType)}
}

func TestCacheAppliesNewAndDeletedDecisions(t *testing.T) {
	cache := NewCache()
	ipDecision := decision(1, "ip", "203.0.113.10", "ban")
	maskedIPDecision := decision(3, "ip", "198.51.100.4/32", "ban")
	rangeDecision := decision(2, "range", "2001:db8::/32", "ban")

	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{ipDecision, maskedIPDecision, rangeDecision}})
	if got := cache.GetBan("203.0.113.10"); got != ipDecision {
		t.Fatalf("expected IP decision, got %#v", got)
	}
	if got := cache.GetBan("2001:db8::42"); got != rangeDecision {
		t.Fatalf("expected range decision, got %#v", got)
	}
	if got := cache.GetBan("198.51.100.4"); got != maskedIPDecision {
		t.Fatalf("expected masked IP decision, got %#v", got)
	}

	cache.Apply(&models.DecisionsStreamResponse{Deleted: []*models.Decision{ipDecision}})
	if got := cache.GetBan("203.0.113.10"); got != nil {
		t.Fatalf("expected deleted decision to be absent, got %#v", got)
	}
}

func TestCacheIgnoresNonBanAndInvalidDecisions(t *testing.T) {
	cache := NewCache()
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{
		decision(1, "ip", "203.0.113.10", "captcha"),
		decision(2, "ip", "not-an-ip", "ban"),
	}})

	if got := cache.GetBan("203.0.113.10"); got != nil {
		t.Fatalf("expected no matching ban, got %#v", got)
	}
}
