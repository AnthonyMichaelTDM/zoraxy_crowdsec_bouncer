package info

import (
	"strings"
	"testing"
)

func TestBouncerUserAgentUsesLAPIFormat(t *testing.T) {
	parts := strings.Split(BOUNCER_USER_AGENT, "/")
	if len(parts) != 2 || parts[0] != BOUNCER_TYPE || parts[1] != VERSION_STRING {
		t.Fatalf("invalid CrowdSec LAPI user agent %q", BOUNCER_USER_AGENT)
	}
}
