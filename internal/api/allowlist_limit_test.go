package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// SEC-11: POST /api/allowlist refuses a two-label entry whose first label is
// co, com, org, net, gov, ac, or edu (it looks like a public suffix, and the
// suffix walk would unblock every site under it) with 400, and refuses a new
// entry once the allowlist holds 1,000 runtime entries with 409. Entries
// from the config allowlist do not count toward the cap.

const allowlistCap = 1000

// addAllowlist posts one allowlist add through h.
func addAllowlist(h http.Handler, domain string) (int, string) {
	rec := serve(h, http.MethodPost, "/api/allowlist", fetchHost,
		map[string]string{"Content-Type": "application/json"}, fmt.Sprintf(`{"domain":%q}`, domain))
	return rec.Code, rec.Body.String()
}

func allowlistHas(entries []string, domain string) bool {
	for _, e := range entries {
		if e == domain {
			return true
		}
	}
	return false
}

func TestAllowlistAdd_RefusesPublicSuffixLike(t *testing.T) {
	// SEC-11 acceptance: co.uk is refused. Every listed first label is
	// refused, in any case and with one trailing root dot, with 400 and a
	// message that names the domain and the reason. The allowlist does not
	// change.
	refused := []string{
		"co.uk", "com.au", "org.uk", "net.au", "gov.uk", "ac.uk", "edu.au",
		"co.jp", "com.br", "gov.in", "ac.jp",
		"CO.UK", "Com.Au", "co.uk.", "CO.UK.",
	}
	for _, d := range refused {
		t.Run(d, func(t *testing.T) {
			s, h, _ := secServer(t)
			code, body := addAllowlist(h, d)
			if code != http.StatusBadRequest {
				t.Fatalf("POST %q = %d, want 400", d, code)
			}
			name := strings.TrimSuffix(strings.ToLower(d), ".")
			if !strings.Contains(strings.ToLower(body), name) {
				t.Errorf("400 body %q does not name the domain %q", body, d)
			}
			if !strings.Contains(strings.ToLower(body), "public suffix") {
				t.Errorf("400 body %q does not say the domain looks like a public suffix", body)
			}
			if n := s.store.AllowlistLen(); n != 0 {
				t.Errorf("allowlist size = %d after a refused add, want 0", n)
			}
		})
	}
}

func TestAllowlistAdd_RefusedSuffixDoesNotUnblock(t *testing.T) {
	// SEC-11: the reason for the check. After a refused co.uk add, a blocked
	// name under co.uk stays blocked.
	s, h, _ := secServer(t)
	s.store.Replace([]string{"ads.tracker.co.uk"})
	if code, _ := addAllowlist(h, "co.uk"); code != http.StatusBadRequest {
		t.Fatalf("POST co.uk = %d, want 400", code)
	}
	if !s.store.IsBlocked("ads.tracker.co.uk") {
		t.Error("ads.tracker.co.uk is not blocked after a refused co.uk add")
	}
}

func TestAllowlistAdd_AcceptsNamesThatOnlyLookSimilar(t *testing.T) {
	// SEC-11: only a two-label name with a listed first label is refused. A
	// name under such a suffix, a two-label name with another first label
	// (github.io-style suffixes pass, no Public Suffix List), and a first
	// label that only starts with a listed one are accepted.
	accepted := []string{
		"example.co.uk", "www.example.com.au", "example.com", "github.io",
		"cobalt.uk", "netflix.com", "comcast.net", "academy.edu", "orgs.au",
		"co.example.uk", "example.co.uk.",
	}
	for _, d := range accepted {
		t.Run(d, func(t *testing.T) {
			s, h, _ := secServer(t)
			if code, body := addAllowlist(h, d); code != http.StatusOK {
				t.Fatalf("POST %q = %d (%q), want 200", d, code, body)
			}
			if n := s.store.AllowlistLen(); n != 1 {
				t.Errorf("allowlist size = %d after adding %q, want 1", n, d)
			}
		})
	}
}

func TestAllowlistAdd_CapRefusesEntry1001(t *testing.T) {
	// SEC-11 acceptance: entry 1,001 is refused. 1,000 runtime adds through
	// the API succeed; the next new entry gets 409 with a message that says
	// the allowlist is full, and the allowlist does not change.
	s, h, _ := secServer(t)
	for i := 0; i < allowlistCap; i++ {
		if code, body := addAllowlist(h, fmt.Sprintf("site%d.example.com", i)); code != http.StatusOK {
			t.Fatalf("add %d = %d (%q), want 200", i+1, code, body)
		}
	}
	if n := s.store.AllowlistLen(); n != allowlistCap {
		t.Fatalf("allowlist size = %d, want %d", n, allowlistCap)
	}
	code, body := addAllowlist(h, "one-more.example.com")
	if code != http.StatusConflict {
		t.Fatalf("add 1,001 = %d (%q), want 409", code, body)
	}
	if !strings.Contains(strings.ToLower(body), "full") {
		t.Errorf("409 body %q does not say the allowlist is full", body)
	}
	if n := s.store.AllowlistLen(); n != allowlistCap {
		t.Errorf("allowlist size = %d after a refused add, want %d", n, allowlistCap)
	}
	if allowlistHas(s.store.GetAllowlist(), "one-more.example.com") {
		t.Error("the refused entry is in the allowlist")
	}
	if !s.store.IsBlocked("ads.example.com") {
		t.Error("ads.example.com is not blocked any more")
	}
}

// configAllowlist returns n config allowlist entries.
func configAllowlist(n int) []string {
	cfg := make([]string, n)
	for i := range cfg {
		cfg[i] = fmt.Sprintf("cfg%d.example.org", i)
	}
	return cfg
}

// fillRuntime adds n runtime entries through the API.
func fillRuntime(t *testing.T, h http.Handler, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if code, body := addAllowlist(h, fmt.Sprintf("api%d.example.com", i)); code != http.StatusOK {
			t.Fatalf("runtime add %d = %d (%q), want 200", i+1, code, body)
		}
	}
}

func TestAllowlistAdd_CapBoundary(t *testing.T) {
	// SEC-11: the cap is exactly 1,000 runtime entries. With 999 a new entry
	// is accepted; once a runtime entry is removed at the cap, its slot is
	// free and a new entry fits again.
	_, h, _ := secServer(t)
	fillRuntime(t, h, allowlistCap-1)
	if code, body := addAllowlist(h, "entry1000.example.com"); code != http.StatusOK {
		t.Fatalf("add with 999 runtime entries = %d (%q), want 200", code, body)
	}
	if code, _ := addAllowlist(h, "entry1001.example.com"); code != http.StatusConflict {
		t.Fatalf("add with 1,000 runtime entries = %d, want 409", code)
	}
	rec := serve(h, http.MethodDelete, "/api/allowlist?domain=api0.example.com", fetchHost, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE = %d, want 200", rec.Code)
	}
	if code, body := addAllowlist(h, "entry1001.example.com"); code != http.StatusOK {
		t.Errorf("add after a runtime removal = %d (%q), want 200", code, body)
	}
	if code, _ := addAllowlist(h, "entry1002.example.com"); code != http.StatusConflict {
		t.Errorf("add after the freed slot is used = %d, want 409", code)
	}
}

func TestAllowlistAdd_ConfigEntriesDoNotCount(t *testing.T) {
	// SEC-11 (maintainer decision): the cap counts only runtime entries.
	// With 1,500 config entries (Store.SetAllowlist), API adds still succeed
	// up to 1,000 runtime entries, and entry 1,001 gets 409.
	s, h, _ := secServer(t)
	s.store.SetAllowlist(configAllowlist(1500))
	if code, body := addAllowlist(h, "first.example.com"); code != http.StatusOK {
		t.Fatalf("add with 1,500 config entries = %d (%q), want 200", code, body)
	}
	fillRuntime(t, h, allowlistCap-1)
	if n := s.store.AllowlistLen(); n != 1500+allowlistCap {
		t.Fatalf("allowlist size = %d, want %d", n, 1500+allowlistCap)
	}
	code, body := addAllowlist(h, "one-more.example.com")
	if code != http.StatusConflict {
		t.Fatalf("add with 1,000 runtime entries = %d (%q), want 409", code, body)
	}
	if n := s.store.AllowlistLen(); n != 1500+allowlistCap {
		t.Errorf("allowlist size = %d after a refused add, want %d", n, 1500+allowlistCap)
	}
}

func TestAllowlistAdd_ConfigDomainUsesNoSlot(t *testing.T) {
	// SEC-11: an API add of a domain that is already a config entry is
	// accepted and uses no slot, so 1,000 new runtime entries still fit.
	s, h, _ := secServer(t)
	s.store.SetAllowlist(configAllowlist(3))
	for _, d := range []string{"cfg0.example.org", "cfg1.example.org", "cfg2.example.org"} {
		if code, body := addAllowlist(h, d); code != http.StatusOK {
			t.Fatalf("add of config entry %q = %d (%q), want 200", d, code, body)
		}
	}
	fillRuntime(t, h, allowlistCap)
	if code, _ := addAllowlist(h, "one-more.example.com"); code != http.StatusConflict {
		t.Errorf("add 1,001 = %d, want 409", code)
	}
	if n := s.store.AllowlistLen(); n != 3+allowlistCap {
		t.Errorf("allowlist size = %d, want %d", n, 3+allowlistCap)
	}
}

func TestAllowlistAdd_ReAddAtCapSucceeds(t *testing.T) {
	// SEC-11: at the cap, re-adding a domain that is already in the
	// allowlist (a runtime entry or a config entry) succeeds, adds nothing,
	// and uses no slot.
	s, h, _ := secServer(t)
	s.store.SetAllowlist(configAllowlist(10))
	fillRuntime(t, h, allowlistCap)
	for _, d := range []string{"api0.example.com", "api999.example.com", "cfg7.example.org"} {
		if code, body := addAllowlist(h, d); code != http.StatusOK {
			t.Errorf("re-add %q at the cap = %d (%q), want 200", d, code, body)
		}
	}
	if n := s.store.AllowlistLen(); n != 10+allowlistCap {
		t.Errorf("allowlist size = %d, want %d", n, 10+allowlistCap)
	}
	if code, _ := addAllowlist(h, "new.example.com"); code != http.StatusConflict {
		t.Errorf("new add after the re-adds = %d, want 409", code)
	}
}

func TestAllowlistAdd_RefusalWritesNoAuditLine(t *testing.T) {
	// SEC-11: a refused add (public suffix or full allowlist) writes no
	// "allowlist entry added" audit line. An accepted add does, so the
	// capture works.
	logs := captureLogs(t)
	s, h, _ := secServer(t)
	if code, _ := addAllowlist(h, "co.uk"); code != http.StatusBadRequest {
		t.Fatalf("POST co.uk = %d, want 400", code)
	}
	if logs.contains("allowlist entry added") {
		t.Errorf("a refused public suffix wrote an audit line: %v", logs.msgs)
	}
	if code, _ := addAllowlist(h, "ok.example.com"); code != http.StatusOK {
		t.Fatalf("POST ok.example.com = %d, want 200", code)
	}
	if !logs.contains("allowlist entry added") {
		t.Fatal("an accepted add wrote no audit line; the capture does not work")
	}
	fillRuntime(t, h, allowlistCap-1)
	logs.mu.Lock()
	logs.msgs = nil
	logs.mu.Unlock()
	if code, _ := addAllowlist(h, "full.example.com"); code != http.StatusConflict {
		t.Fatalf("POST at the cap = %d, want 409", code)
	}
	if logs.contains("allowlist entry added") || logs.contains("full.example.com") {
		t.Errorf("a refused add at the cap wrote an audit line: %v", logs.msgs)
	}
	if s.store.AllowlistLen() != allowlistCap {
		t.Errorf("allowlist size = %d, want %d", s.store.AllowlistLen(), allowlistCap)
	}
}
