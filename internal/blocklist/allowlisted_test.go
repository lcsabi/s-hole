package blocklist

import "testing"

func TestStore_IsAllowlisted(t *testing.T) {
	// CL 117 req 12: IsAllowlisted is true when the domain or a parent of it is
	// on the allowlist, in any letter case and with or without the trailing
	// dot. It follows the allowlist only: a blocked name is not allowlisted,
	// and a child of an entry does not allowlist its parent.
	s := NewStore()
	s.Replace([]string{"tracker.example", "ads.shop.example"})
	s.SetAllowlist([]string{"shop.example", "Safe.Tracker.Example."})

	cases := []struct {
		domain string
		want   bool
	}{
		{"shop.example", true},
		{"shop.example.", true},
		{"metrics.shop.example", true},
		{"METRICS.Shop.Example.", true},
		{"ads.shop.example", true}, // a parent is allowlisted, also when the name is blocked
		{"safe.tracker.example", true},
		{"x.safe.tracker.example.", true},
		{"tracker.example", false}, // the entry is a child, not a parent
		{"other.tracker.example", false},
		{"example", false},
		{"myshop.example", false}, // a label boundary, not a string suffix
		{"shop.example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := s.IsAllowlisted(tc.domain); got != tc.want {
			t.Errorf("IsAllowlisted(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestStore_IsAllowlistedFollowsRuntimeChanges(t *testing.T) {
	// CL 117 req 12: an allowlist change through the API applies at once.
	s := NewStore()
	if s.IsAllowlisted("a.shop.example") {
		t.Fatal("empty store reports an allowlisted name")
	}
	if !s.AddToAllowlistLimited("shop.example", 10) {
		t.Fatal("AddToAllowlistLimited refused the entry")
	}
	if !s.IsAllowlisted("a.shop.example") {
		t.Error("IsAllowlisted = false after the add, want true")
	}
	s.RemoveFromAllowlist("shop.example")
	if s.IsAllowlisted("a.shop.example") {
		t.Error("IsAllowlisted = true after the remove, want false")
	}
}
