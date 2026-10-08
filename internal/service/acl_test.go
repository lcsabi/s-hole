package service

// Tests for the access-list rules of the Windows service (b/104). The rules
// are plain data and arithmetic, so these tests run on every platform.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Well-known SIDs that the tests use.
const (
	tSystem       = "S-1-5-18"
	tAdmins       = "S-1-5-32-544"
	tUsers        = "S-1-5-32-545"
	tAuthUsers    = "S-1-5-11"
	tEveryone     = "S-1-1-0"
	tLocal        = "S-1-2-0"
	tConsoleLogon = "S-1-2-1"
	tService      = "S-1-5-6"
	tThisOrg      = "S-1-5-15"
	tAllServices  = "S-1-5-80-0"
	tCreatorOwner = "S-1-3-0"
	tOwnerRights  = "S-1-3-4"
	tInteractive  = "S-1-5-4"
	tAppPackages  = "S-1-15-2-1"
	tAlice        = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	tInheritedACE = 0x10 // INHERITED_ACE: readACL passes it through
)

// tWriteLike is every right that lets a holder change, delete, or take over
// a file: write data, append, write EA, delete child, write attributes,
// DELETE, WRITE_DAC, and WRITE_OWNER.
const tWriteLike = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000

// tSvcSID is the SID of a test service, so the tests do not depend on the
// name s-hole.
var tSvcSID = serviceSID("s-hole")

func TestServiceSID_KnownValues(t *testing.T) {
	// b/104: the service SID is S-1-5-80- and the SHA-1 of the upper-case
	// name in UTF-16LE. Windows publishes these two values.
	cases := map[string]string{
		"TrustedInstaller": "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
		"MSSQLSERVER":      "S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003",
	}
	for name, want := range cases {
		if got := serviceSID(name); got != want {
			t.Errorf("serviceSID(%q) = %s, want %s", name, got, want)
		}
	}
}

func TestServiceSID_CaseDoesNotMatter(t *testing.T) {
	// b/104: Windows upper-cases the name before the hash, so the case of
	// the name does not change the SID.
	want := serviceSID("TrustedInstaller")
	for _, name := range []string{"trustedinstaller", "TRUSTEDINSTALLER", "tRuStEdInStAlLeR"} {
		if got := serviceSID(name); got != want {
			t.Errorf("serviceSID(%q) = %s, want %s", name, got, want)
		}
	}
	if serviceSID("s-hole") != serviceSID("S-HOLE") {
		t.Errorf("serviceSID(s-hole) = %s differs from serviceSID(S-HOLE) = %s", serviceSID("s-hole"), serviceSID("S-HOLE"))
	}
}

func TestServiceSID_Shape(t *testing.T) {
	// b/104: S-1-5-80 and five 32-bit sub-authorities; another name gives
	// another SID.
	re := regexp.MustCompile(`^S-1-5-80(-[0-9]+){5}$`)
	for _, name := range []string{"s-hole", "a", "TrustedInstaller"} {
		sid := serviceSID(name)
		if !re.MatchString(sid) {
			t.Errorf("serviceSID(%q) = %s, want S-1-5-80 and five sub-authorities", name, sid)
			continue
		}
		for _, p := range strings.Split(sid, "-")[4:] {
			if _, err := strconv.ParseUint(p, 10, 32); err != nil {
				t.Errorf("serviceSID(%q): sub-authority %s is not a 32-bit number", name, p)
			}
		}
	}
	if serviceSID("s-hole") == serviceSID("s-hole2") {
		t.Error("two service names give the same SID")
	}
}

func TestServiceTokenSIDs_ExactSet(t *testing.T) {
	// b/104: the binary check counts the service SID and every group in the
	// token of a virtual-account service, and no other SID. CONSOLE LOGON
	// was in the token of NT SERVICE\s-hole on Windows 10 (whoami /groups).
	got := serviceTokenSIDs(tSvcSID)
	want := []string{tSvcSID, tEveryone, tLocal, tConsoleLogon, tService, tAuthUsers, tThisOrg, tUsers, tAllServices}
	if len(got) != 9 {
		t.Errorf("serviceTokenSIDs has %d SIDs, want 9", len(got))
	}
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if strings.Join(g, ",") != strings.Join(w, ",") {
		t.Errorf("serviceTokenSIDs = %v, want the set %v", got, want)
	}
	for _, s := range []string{tSystem, tAdmins, tInteractive, tCreatorOwner, tOwnerRights} {
		for _, h := range got {
			if h == s {
				t.Errorf("serviceTokenSIDs holds %s, which a virtual-account service does not get", s)
			}
		}
	}
}

// sddlACE is the SDDL form of one entry, as Windows parses it.
var sddlACE = regexp.MustCompile(`^\((A|D);((?:OI|CI|IO)*);0x([0-9a-fA-F]+);;;(S-1-[0-9]+(?:-[0-9]+)+)\)`)

// parseSDDL parses a DACL string that sddl wrote. It fails the test when the
// string does not start with D:P or holds an entry that is not a standard
// allow or deny entry.
func parseSDDL(t *testing.T, s string) []ace {
	t.Helper()
	rest, ok := strings.CutPrefix(s, "D:P")
	if !ok {
		t.Fatalf("SDDL %q does not start with D:P (protected DACL)", s)
	}
	if strings.HasPrefix(rest, "AI") || strings.HasPrefix(rest, "AR") {
		t.Fatalf("SDDL %q has more DACL flags than P", s)
	}
	var out []ace
	for rest != "" {
		m := sddlACE.FindStringSubmatch(rest)
		if m == nil {
			t.Fatalf("SDDL %q: cannot parse the entry at %q", s, rest)
		}
		rest = rest[len(m[0]):]
		var e ace
		e.deny = m[1] == "D"
		for i := 0; i < len(m[2]); i += 2 {
			switch m[2][i : i+2] {
			case "OI":
				e.flags |= 0x1
			case "CI":
				e.flags |= 0x2
			case "IO":
				e.flags |= 0x8
			}
		}
		mask, err := strconv.ParseUint(m[3], 16, 32)
		if err != nil {
			t.Fatalf("SDDL %q: mask %s: %v", s, m[3], err)
		}
		e.mask = uint32(mask)
		e.sid = m[4]
		out = append(out, e)
	}
	return out
}

// childACL returns the entries that a new file (folder false) or a new
// subfolder (folder true) with this owner inherits from a parent folder with
// acl, as Windows applies inheritance. Only the entries that apply to the
// child itself are returned; generic rights stay as they are, so
// grantedRights must map them.
func childACL(acl []ace, owner string, folder bool) []ace {
	var out []ace
	for _, e := range acl {
		inheritBit := uint8(0x1) // object inherit, for a file
		if folder {
			inheritBit = 0x2 // container inherit, for a folder
		}
		if e.flags&inheritBit == 0 {
			continue
		}
		c := ace{deny: e.deny, flags: tInheritedACE, mask: e.mask, sid: e.sid}
		if c.sid == tCreatorOwner {
			c.sid = owner
		}
		out = append(out, c)
	}
	return out
}

func TestSDDL_ServiceDirACLIsProtectedAndParses(t *testing.T) {
	// b/104: the config folder gets a protected DACL (D:P), so no entry of
	// the parent folder reaches it, and every entry has the standard form.
	s := sddl(serviceDirACL(tSvcSID))
	if !strings.HasPrefix(s, "D:P(") {
		t.Fatalf("sddl = %q, want it to start with D:P(", s)
	}
	got := parseSDDL(t, s)
	if len(got) != len(serviceDirACL(tSvcSID)) {
		t.Errorf("SDDL has %d entries, the ACE list has %d", len(got), len(serviceDirACL(tSvcSID)))
	}
}

func TestSDDL_RoundTrip(t *testing.T) {
	// b/104: sddl writes the type, every flag, the mask, and the SID of each
	// entry, so Windows gets the list that the code evaluates.
	in := []ace{
		{flags: 0, mask: 0x1, sid: tSystem},
		{flags: 0x1, mask: 0x2, sid: tAdmins},
		{flags: 0x2, mask: 0x1f01ff, sid: tUsers},
		{flags: 0x1 | 0x2, mask: 0x1200a9, sid: tSvcSID},
		{flags: 0x1 | 0x2 | 0x8, mask: 0x10000000, sid: tCreatorOwner},
		{deny: true, flags: 0x1 | 0x8, mask: 0x10000, sid: tEveryone},
		{deny: true, flags: 0x2 | 0x8, mask: 0x80000000, sid: tAuthUsers},
	}
	s := sddl(in)
	got := parseSDDL(t, s)
	if fmt.Sprint(got) != fmt.Sprint(in) {
		t.Errorf("sddl(%v) = %q, parses back as %v", in, s, got)
	}
	if !strings.Contains(strings.ToLower(s), strings.ToLower("(D;OIIO;0x10000;;;S-1-1-0)")) {
		t.Errorf("sddl = %q, want the deny entry (D;OIIO;0x10000;;;S-1-1-0)", s)
	}
	if got := sddl(nil); got != "D:P" {
		t.Errorf("sddl(nil) = %q, want D:P", got)
	}
}

func TestServiceDirACL_Entries(t *testing.T) {
	// b/104: SYSTEM and Administrators get inherited full control; the
	// service gets inherited read and execute, plus add file and add
	// subfolder on the folder itself only; CREATOR OWNER gets inherit-only
	// full control. No other SID is in the list.
	for name, acl := range map[string][]ace{
		"ace list":    serviceDirACL(tSvcSID),
		"parsed SDDL": parseSDDL(t, sddl(serviceDirACL(tSvcSID))),
	} {
		t.Run(name, func(t *testing.T) {
			var svcInherited, svcFolderOnly uint32
			seen := map[string]bool{}
			for _, e := range acl {
				seen[e.sid] = true
				switch e.sid {
				case tSystem, tAdmins:
					if e.deny || e.flags != 0x3 || e.mask != 0x1f01ff {
						t.Errorf("entry %+v, want allow OI CI 0x1f01ff", e)
					}
				case tCreatorOwner:
					if e.deny || e.flags != 0xb || e.mask != 0x1f01ff {
						t.Errorf("entry %+v, want allow OI CI IO 0x1f01ff", e)
					}
				case tSvcSID:
					switch {
					case e.deny:
						t.Errorf("entry %+v: a deny entry for the service is not in the design", e)
					case e.flags == 0x3:
						svcInherited |= e.mask
					case e.flags == 0:
						svcFolderOnly |= e.mask
					default:
						t.Errorf("service entry %+v has flags 0x%x, want OI CI or none", e, e.flags)
					}
				default:
					t.Errorf("entry for SID %s, want no entry for a SID other than SYSTEM, Administrators, the service, and CREATOR OWNER", e.sid)
				}
			}
			for _, s := range []string{tSystem, tAdmins, tCreatorOwner, tSvcSID} {
				if !seen[s] {
					t.Errorf("no entry for %s", s)
				}
			}
			if svcInherited != 0x1200a9 {
				t.Errorf("inherited service rights = 0x%x, want 0x1200a9 (read and execute)", svcInherited)
			}
			if svcFolderOnly != 0x6 {
				t.Errorf("folder-only service rights = 0x%x, want 0x6 (add file, add subfolder)", svcFolderOnly)
			}
		})
	}
}

func TestServiceDirACL_WhatEachAccountGets(t *testing.T) {
	// b/104: evaluate the list that Windows gets (the parsed SDDL) for the
	// folder, a file and a subfolder that an administrator puts in it (such
	// as config.yaml), and a file and a subfolder that the service creates.
	// The service must never get a write, delete, change-permission, or
	// take-ownership right on what an administrator created.
	dir := parseSDDL(t, sddl(serviceDirACL(tSvcSID)))
	svc := serviceTokenSIDs(tSvcSID)
	cases := []struct {
		name  string
		owner string
		acl   []ace
		sids  []string
		want  uint32
	}{
		{"folder: service", tAdmins, dir, svc, 0x1200a9 | 0x6},
		{"folder: SYSTEM", tAdmins, dir, []string{tSystem}, 0x1f01ff},
		{"folder: Administrators", tSystem, dir, []string{tAdmins}, 0x1f01ff},
		{"folder: other user", tAdmins, dir, []string{tAlice, tUsers, tAuthUsers, tEveryone, tInteractive}, 0},
		{"admin file: service", tAdmins, childACL(dir, tAdmins, false), svc, 0x1200a9},
		{"admin file: Administrators", tAdmins, childACL(dir, tAdmins, false), []string{tAdmins}, 0x1f01ff},
		{"admin file: other user", tAdmins, childACL(dir, tAdmins, false), []string{tAlice, tUsers, tAuthUsers, tEveryone, tInteractive}, 0},
		{"admin subfolder: service", tAdmins, childACL(dir, tAdmins, true), svc, 0x1200a9},
		{"service file: service", tSvcSID, childACL(dir, tSvcSID, false), svc, 0x1f01ff},
		{"service subfolder: service", tSvcSID, childACL(dir, tSvcSID, true), svc, 0x1f01ff},
		{"service file: other user", tSvcSID, childACL(dir, tSvcSID, false), []string{tAlice, tUsers, tAuthUsers, tEveryone, tInteractive}, 0},
	}
	for _, c := range cases {
		if got := grantedRights(c.owner, c.acl, false, c.sids); got != c.want {
			t.Errorf("%s: rights = 0x%x, want 0x%x", c.name, got, c.want)
		}
	}
	// The same, through the ACE list directly.
	adminFile := childACL(serviceDirACL(tSvcSID), tAdmins, false)
	if got := grantedRights(tAdmins, adminFile, false, svc); got&tWriteLike != 0 {
		t.Errorf("the service gets 0x%x (%s) on config.yaml, want no write right", got&tWriteLike, rightNames(got))
	}
}

func TestServiceDirACL_OldModifyListIsCaught(t *testing.T) {
	// b/104: before the fix, the service got inherited modify (0x1301bf)
	// on the config folder. The evaluation must report that a file in that
	// folder (config.yaml or s-hole.exe) can be changed and deleted.
	old := []ace{
		{flags: 0x3, mask: 0x1f01ff, sid: tSystem},
		{flags: 0x3, mask: 0x1f01ff, sid: tAdmins},
		{flags: 0x3, mask: 0x1301bf, sid: tSvcSID},
	}
	got := grantedRights(tAdmins, childACL(old, tAdmins, false), false, serviceTokenSIDs(tSvcSID))
	if got&binaryFileWrite != 0x2|0x4|0x10000 {
		t.Errorf("rights on a file under the old list = 0x%x, want write, append, and delete", got)
	}
}

func TestMapGeneric(t *testing.T) {
	// b/104: generic rights map to the file rights; other bits stay.
	cases := []struct{ in, want uint32 }{
		{0, 0},
		{0x10000000, 0x1f01ff},
		{0x20000000, 0x1200a0},
		{0x40000000, 0x120116},
		{0x80000000, 0x120089},
		{0x80000000 | 0x20000000, 0x1200a9},
		{0x40000000 | 0x80000000, 0x120116 | 0x120089},
		{0x80000000 | 0x10000, 0x120089 | 0x10000},
		{0x10000 | 0x2, 0x10000 | 0x2},
		{0x1301bf, 0x1301bf},
		{0xf0000000, 0x1f01ff},
	}
	for _, c := range cases {
		if got := mapGeneric(c.in); got != c.want {
			t.Errorf("mapGeneric(0x%x) = 0x%x, want 0x%x", c.in, got, c.want)
		}
	}
}

func TestGrantedRights_AccessCheck(t *testing.T) {
	// b/104: grantedRights follows the Windows access check.
	me := []string{tAlice, tUsers}
	cases := []struct {
		name  string
		owner string
		acl   []ace
		null  bool
		want  uint32
	}{
		{"null DACL grants everything", tSystem, nil, true, 0x1f01ff},
		{"null DACL ignores entries", tSystem, []ace{{deny: true, mask: 0x1f01ff, sid: tAlice}}, true, 0x1f01ff},
		{"empty DACL grants nothing", tSystem, []ace{}, false, 0},
		{"nil DACL that is not null grants nothing", tSystem, nil, false, 0},
		{"allow to a held SID", tSystem, []ace{{mask: 0x3, sid: tAlice}}, false, 0x3},
		{"allows to two held SIDs add up", tSystem, []ace{{mask: 0x1, sid: tAlice}, {mask: 0x2, sid: tUsers}}, false, 0x3},
		{"allow to a SID not held", tSystem, []ace{{mask: 0x1f01ff, sid: tAdmins}}, false, 0},
		{"deny to a SID not held", tSystem, []ace{{deny: true, mask: 0x2, sid: tAdmins}, {mask: 0x3, sid: tAlice}}, false, 0x3},
		{"earlier deny wins", tSystem, []ace{{deny: true, mask: 0x2, sid: tUsers}, {mask: 0x3, sid: tAlice}}, false, 0x1},
		{"later deny does not remove", tSystem, []ace{{mask: 0x3, sid: tAlice}, {deny: true, mask: 0x2, sid: tUsers}}, false, 0x3},
		{"later deny blocks a later allow", tSystem, []ace{{mask: 0x1, sid: tAlice}, {deny: true, mask: 0x3, sid: tUsers}, {mask: 0x3, sid: tAlice}}, false, 0x1},
		{"inherit-only allow does not apply", tSystem, []ace{{flags: 0xb, mask: 0x1f01ff, sid: tAlice}}, false, 0},
		{"inherit-only deny does not apply", tSystem, []ace{{deny: true, flags: 0x9, mask: 0x2, sid: tAlice}, {mask: 0x3, sid: tAlice}}, false, 0x3},
		{"inherited entry applies", tSystem, []ace{{flags: tInheritedACE | 0x3, mask: 0x2, sid: tAlice}}, false, 0x2},
		{"generic all in allow", tSystem, []ace{{mask: 0x10000000, sid: tAlice}}, false, 0x1f01ff},
		{"generic write in allow", tSystem, []ace{{mask: 0x40000000, sid: tAlice}}, false, 0x120116},
		{"generic read in deny", tSystem, []ace{{deny: true, mask: 0x80000000, sid: tAlice}, {mask: 0x1f01ff, sid: tAlice}}, false, 0x1f01ff &^ 0x120089},
		{"owner gets read control and change permissions", tAlice, nil, false, 0x20000 | 0x40000},
		{"owner rights add to entries", tAlice, []ace{{mask: 0x1, sid: tUsers}}, false, 0x1 | 0x20000 | 0x40000},
		{"owner by group", tUsers, nil, false, 0x20000 | 0x40000},
		{"owner rights survive a deny", tAlice, []ace{{deny: true, mask: 0x40000, sid: tAlice}}, false, 0x20000 | 0x40000},
		{"owner not held", tAdmins, nil, false, 0},
		{"OWNER RIGHTS entry replaces the implicit rights", tAlice, []ace{{mask: 0x1, sid: tOwnerRights}}, false, 0x1},
		{"OWNER RIGHTS entry with no change permissions", tAlice, []ace{{mask: 0x20000, sid: tOwnerRights}, {mask: 0x2, sid: tUsers}}, false, 0x20000 | 0x2},
		{"OWNER RIGHTS deny", tAlice, []ace{{deny: true, mask: 0x40000, sid: tOwnerRights}, {mask: 0x1f01ff, sid: tAlice}}, false, 0x1f01ff &^ 0x40000},
		{"OWNER RIGHTS entry for a holder that is not the owner", tAdmins, []ace{{mask: 0x1f01ff, sid: tOwnerRights}}, false, 0},
	}
	for _, c := range cases {
		if got := grantedRights(c.owner, c.acl, c.null, me); got != c.want {
			t.Errorf("%s: grantedRights = 0x%x, want 0x%x", c.name, got, c.want)
		}
	}
}

func TestBinaryRightConstants(t *testing.T) {
	// b/104: the rights that count for the binary, its folder, and the
	// folders above it.
	if binaryFileWrite != 0x2|0x4|0x10000|0x40000|0x80000 {
		t.Errorf("binaryFileWrite = 0x%x", binaryFileWrite)
	}
	if binaryFolderWrite != 0x2|0x4|0x40|0x10000|0x40000|0x80000 {
		t.Errorf("binaryFolderWrite = 0x%x", binaryFolderWrite)
	}
	if parentFolderWrite != 0x40|0x10000|0x40000|0x80000 {
		t.Errorf("parentFolderWrite = 0x%x", parentFolderWrite)
	}
}

func TestBinaryPaths(t *testing.T) {
	// b/104: the file, its folder, and every folder above it up to the
	// drive root or the share (\\server is not a folder).
	const (
		file   = 0x2 | 0x4 | 0x10000 | 0x40000 | 0x80000
		folder = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000
		parent = 0x40 | 0x10000 | 0x40000 | 0x80000
	)
	cases := []struct {
		exe  string
		want []pathCheck
	}{
		{`C:\Program Files\s-hole\s-hole.exe`, []pathCheck{
			{`C:\Program Files\s-hole\s-hole.exe`, file},
			{`C:\Program Files\s-hole`, folder},
			{`C:\Program Files`, parent},
			{`C:\`, parent},
		}},
		{`C:\s-hole.exe`, []pathCheck{
			{`C:\s-hole.exe`, file},
			{`C:\`, folder},
		}},
		{`d:\a\b\c\s-hole.exe`, []pathCheck{
			{`d:\a\b\c\s-hole.exe`, file},
			{`d:\a\b\c`, folder},
			{`d:\a\b`, parent},
			{`d:\a`, parent},
			{`d:\`, parent},
		}},
		{`\\server\share\dir\s-hole.exe`, []pathCheck{
			{`\\server\share\dir\s-hole.exe`, file},
			{`\\server\share\dir`, folder},
			{`\\server\share`, parent},
		}},
		{`\\server\share\s-hole.exe`, []pathCheck{
			{`\\server\share\s-hole.exe`, file},
			{`\\server\share`, folder},
		}},
	}
	for _, c := range cases {
		got := binaryPaths(c.exe)
		if fmt.Sprintf("%#v", got) != fmt.Sprintf("%#v", c.want) {
			t.Errorf("binaryPaths(%s):\n got %s\nwant %s", c.exe, fmtChecks(got), fmtChecks(c.want))
		}
		for _, p := range got {
			if p.path == `\\server` || p.path == `\\server\` || p.path == "" || p.path == `\` {
				t.Errorf("binaryPaths(%s) checks %q, which is not a folder", c.exe, p.path)
			}
		}
	}
}

func fmtChecks(cs []pathCheck) string {
	var b []string
	for _, c := range cs {
		b = append(b, fmt.Sprintf("%s=0x%x", c.path, c.rights))
	}
	return strings.Join(b, " | ")
}

func TestRightNames(t *testing.T) {
	// b/104: an error names each right that it found.
	names := map[uint32]string{
		0x2:     "write or add file",
		0x4:     "append or add subfolder",
		0x40:    "delete child",
		0x10000: "delete",
		0x40000: "change permissions",
		0x80000: "take ownership",
	}
	for bit, name := range names {
		if got := rightNames(bit); got != name {
			t.Errorf("rightNames(0x%x) = %q, want %q", bit, got, name)
		}
	}
	all := rightNames(0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000)
	for _, name := range names {
		if !strings.Contains(all, name) {
			t.Errorf("rightNames(all) = %q, does not name %q", all, name)
		}
	}
	// "delete" is also in "delete child": the full mask must hold both.
	if strings.Count(all, "delete") != 2 {
		t.Errorf("rightNames(all) = %q, want both delete child and delete", all)
	}
	if got := rightNames(0x1 | 0x20 | 0x20000 | 0x100000); got != "" {
		t.Errorf("rightNames(read rights) = %q, want no name", got)
	}
	if got := rightNames(0x10000 | 0x2); !strings.Contains(got, "write or add file") || !strings.Contains(got, "delete") || strings.Contains(got, "delete child") {
		t.Errorf("rightNames(write, delete) = %q", got)
	}
}

// objACL is the owner and access list of one path, as readACL returns them.
type objACL struct {
	owner string
	acl   []ace
	null  bool
}

// evalBinary runs the binary check of checkBinary over fake access lists:
// for each path of binaryPaths(exe), the rights in the check that the holder
// of sids gets. A path without an access list fails the test (fail closed).
func evalBinary(t *testing.T, exe string, fs map[string]objACL, sids []string) map[string]uint32 {
	t.Helper()
	found := map[string]uint32{}
	for _, c := range binaryPaths(exe) {
		o, ok := fs[c.path]
		if !ok {
			t.Fatalf("no access list for %s", c.path)
		}
		if got := grantedRights(o.owner, o.acl, o.null, sids) & c.rights; got != 0 {
			found[c.path] = got
		}
	}
	return found
}

// Realistic access lists of a Windows 10/11 system disk, as readACL returns
// them: raw masks (generic rights not mapped), and the inherited flag on
// inherited entries.
var (
	tTI = serviceSID("TrustedInstaller")

	// C:\ (the drive root).
	aclDriveRoot = objACL{owner: tSystem, acl: []ace{
		{flags: 0x3, mask: 0x1f01ff, sid: tAdmins},
		{flags: 0x3, mask: 0x1f01ff, sid: tSystem},
		{flags: 0x3, mask: 0x1200a9, sid: tUsers},
		{flags: 0xb, mask: 0x10000 | 0xe0000000, sid: tAuthUsers}, // modify, files and subfolders only
		{flags: 0, mask: 0x4, sid: tAuthUsers},                    // create folders
	}}

	// C:\Program Files.
	aclProgramFiles = objACL{owner: tTI, acl: []ace{
		{flags: 0, mask: 0x1f01ff, sid: tTI},
		{flags: 0xa, mask: 0x10000000, sid: tTI},
		{flags: 0, mask: 0x1301bf, sid: tSystem},
		{flags: 0xb, mask: 0x10000000, sid: tSystem},
		{flags: 0, mask: 0x1301bf, sid: tAdmins},
		{flags: 0xb, mask: 0x10000000, sid: tAdmins},
		{flags: 0, mask: 0x1200a9, sid: tUsers},
		{flags: 0xb, mask: 0xa0000000, sid: tUsers},
		{flags: 0xb, mask: 0x10000000, sid: tCreatorOwner},
		{flags: 0, mask: 0x1200a9, sid: tAppPackages},
		{flags: 0xb, mask: 0xa0000000, sid: tAppPackages},
	}}

	// C:\Program Files\s-hole, made by an administrator.
	aclProgramFilesSub = objACL{owner: tAdmins, acl: []ace{
		{flags: tInheritedACE, mask: 0x1f01ff, sid: tTI},
		{flags: tInheritedACE | 0xa, mask: 0x10000000, sid: tTI},
		{flags: tInheritedACE, mask: 0x1f01ff, sid: tSystem},
		{flags: tInheritedACE | 0xb, mask: 0x10000000, sid: tSystem},
		{flags: tInheritedACE, mask: 0x1f01ff, sid: tAdmins},
		{flags: tInheritedACE | 0xb, mask: 0x10000000, sid: tAdmins},
		{flags: tInheritedACE, mask: 0x1200a9, sid: tUsers},
		{flags: tInheritedACE | 0xb, mask: 0xa0000000, sid: tUsers},
		{flags: tInheritedACE | 0xb, mask: 0x10000000, sid: tCreatorOwner},
		{flags: tInheritedACE, mask: 0x1200a9, sid: tAppPackages},
		{flags: tInheritedACE | 0xb, mask: 0xa0000000, sid: tAppPackages},
	}}

	// C:\Program Files\s-hole\s-hole.exe, copied in by an administrator.
	aclProgramFilesExe = objACL{owner: tAdmins, acl: []ace{
		{flags: tInheritedACE, mask: 0x1f01ff, sid: tSystem},
		{flags: tInheritedACE, mask: 0x1f01ff, sid: tAdmins},
		{flags: tInheritedACE, mask: 0x1200a9, sid: tUsers},
		{flags: tInheritedACE, mask: 0x1200a9, sid: tAppPackages},
	}}

	// C:\ProgramData.
	aclProgramData = objACL{owner: tSystem, acl: []ace{
		{flags: 0x3, mask: 0x1f01ff, sid: tSystem},
		{flags: 0x3, mask: 0x1f01ff, sid: tAdmins},
		{flags: 0xb, mask: 0x10000000, sid: tCreatorOwner},
		{flags: 0x3, mask: 0x1200a9, sid: tUsers},
		{flags: 0x2, mask: 0x116, sid: tUsers}, // write data, append, write EA, write attributes: this folder and subfolders
	}}

	// C:\ProgramData\s-hole, made by an administrator.
	aclProgramDataSub = objACL{owner: tAdmins, acl: []ace{
		{flags: tInheritedACE | 0x3, mask: 0x1f01ff, sid: tSystem},
		{flags: tInheritedACE | 0x3, mask: 0x1f01ff, sid: tAdmins},
		{flags: tInheritedACE | 0xb, mask: 0x10000000, sid: tCreatorOwner},
		{flags: tInheritedACE, mask: 0x1f01ff, sid: tAdmins}, // CREATOR OWNER for the owner
		{flags: tInheritedACE | 0x3, mask: 0x1200a9, sid: tUsers},
		{flags: tInheritedACE | 0x2, mask: 0x116, sid: tUsers},
	}}

	// C:\s-hole, made by the user alice (the old README layout).
	aclRootSub = objACL{owner: tAlice, acl: []ace{
		{flags: tInheritedACE | 0x3, mask: 0x1f01ff, sid: tAdmins},
		{flags: tInheritedACE | 0x3, mask: 0x1f01ff, sid: tSystem},
		{flags: tInheritedACE | 0x3, mask: 0x1200a9, sid: tUsers},
		{flags: tInheritedACE, mask: 0x1301bf, sid: tAuthUsers},
		{flags: tInheritedACE | 0xb, mask: 0x10000 | 0xe0000000, sid: tAuthUsers},
		{flags: tInheritedACE, mask: 0x1f01ff, sid: tAlice},
		{flags: tInheritedACE | 0xb, mask: 0x10000000, sid: tCreatorOwner},
	}}

	// A file in C:\s-hole that alice copied in.
	aclRootSubFile = objACL{owner: tAlice, acl: []ace{
		{flags: tInheritedACE, mask: 0x1f01ff, sid: tAdmins},
		{flags: tInheritedACE, mask: 0x1f01ff, sid: tSystem},
		{flags: tInheritedACE, mask: 0x1200a9, sid: tUsers},
		{flags: tInheritedACE, mask: 0x10000 | 0xe0000000, sid: tAuthUsers},
		{flags: tInheritedACE, mask: 0x1f01ff, sid: tAlice},
	}}
)

func TestBinaryCheck_ProgramFilesIsSafe(t *testing.T) {
	// b/104: the decided layout. Under the default access lists of
	// C:\Program Files, the service account cannot change the binary.
	exe := `C:\Program Files\s-hole\s-hole.exe`
	fs := map[string]objACL{
		exe:                       aclProgramFilesExe,
		`C:\Program Files\s-hole`: aclProgramFilesSub,
		`C:\Program Files`:        aclProgramFiles,
		`C:\`:                     aclDriveRoot,
	}
	if got := evalBinary(t, exe, fs, serviceTokenSIDs(tSvcSID)); len(got) != 0 {
		t.Errorf("binary check found %v, want nothing", got)
	}
	// An administrator could change it: the check is not empty by accident.
	if got := evalBinary(t, exe, fs, []string{tAdmins}); len(got) == 0 {
		t.Error("binary check found nothing for Administrators, want the file and its folder")
	}
}

func TestBinaryCheck_FolderUnderDriveRootIsRefused(t *testing.T) {
	// b/104: a folder that a user made under C:\ (the old README layout)
	// gives Authenticated Users, and so the service, modify on the binary
	// and on its folder.
	exe := `C:\s-hole\s-hole.exe`
	fs := map[string]objACL{
		exe:         aclRootSubFile,
		`C:\s-hole`: aclRootSub,
		`C:\`:       aclDriveRoot,
	}
	got := evalBinary(t, exe, fs, serviceTokenSIDs(tSvcSID))
	want := map[string]uint32{
		exe:         0x2 | 0x4 | 0x10000,
		`C:\s-hole`: 0x2 | 0x4 | 0x10000,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("binary check found %v, want %v", got, want)
	}
	n := rightNames(got[exe])
	for _, want := range []string{"write or add file", "append or add subfolder", "delete"} {
		if !strings.Contains(n, want) {
			t.Errorf("rightNames = %q, does not name %q", n, want)
		}
	}
	if strings.Contains(n, "delete child") {
		t.Errorf("rightNames = %q names delete child, which the service does not have", n)
	}
}

func TestBinaryCheck_BinaryAtDriveRootIsRefused(t *testing.T) {
	// b/104: Authenticated Users can create folders in C:\, so a binary in
	// C:\ itself could get a planted subfolder next to it.
	exe := `C:\s-hole.exe`
	fs := map[string]objACL{
		exe:   aclProgramFilesExe,
		`C:\`: aclDriveRoot,
	}
	got := evalBinary(t, exe, fs, serviceTokenSIDs(tSvcSID))
	if got[`C:\`] != 0x4 || len(got) != 1 {
		t.Errorf("binary check found %v, want only C:\\ with add subfolder", got)
	}
}

func TestBinaryCheck_ProgramDataFolderIsRefused(t *testing.T) {
	// b/104: Users can add files to a folder under C:\ProgramData, so the
	// binary must not live there. C:\ProgramData itself is only a folder
	// above the binary's folder, where add file does not count.
	exe := `C:\ProgramData\s-hole\s-hole.exe`
	fs := map[string]objACL{
		exe:                     aclProgramFilesExe,
		`C:\ProgramData\s-hole`: aclProgramDataSub,
		`C:\ProgramData`:        aclProgramData,
		`C:\`:                   aclDriveRoot,
	}
	got := evalBinary(t, exe, fs, serviceTokenSIDs(tSvcSID))
	want := map[string]uint32{`C:\ProgramData\s-hole`: 0x2 | 0x4}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("binary check found %v, want %v", got, want)
	}
}

func TestBinaryCheck_EachTokenGroupCounts(t *testing.T) {
	// b/104: an entry for any SID in the service token gives the service
	// that right; an entry for a SID outside the token does not.
	exe := `C:\Program Files\s-hole\s-hole.exe`
	for _, sid := range append(serviceTokenSIDs(tSvcSID), tInteractive, tAlice, tAdmins) {
		file := aclProgramFilesExe
		file.acl = append(append([]ace(nil), file.acl...), ace{mask: 0x2, sid: sid})
		fs := map[string]objACL{
			exe:                       file,
			`C:\Program Files\s-hole`: aclProgramFilesSub,
			`C:\Program Files`:        aclProgramFiles,
			`C:\`:                     aclDriveRoot,
		}
		got := evalBinary(t, exe, fs, serviceTokenSIDs(tSvcSID))
		inToken := sid != tInteractive && sid != tAlice && sid != tAdmins
		if inToken && got[exe] != 0x2 {
			t.Errorf("write data for %s on the binary: found %v, want the binary with write data", sid, got)
		}
		if !inToken && len(got) != 0 {
			t.Errorf("write data for %s (not in the token): found %v, want nothing", sid, got)
		}
	}
}

func TestBinaryCheck_FolderAboveRights(t *testing.T) {
	// b/104: on a folder above the binary's folder, delete child, delete,
	// change permissions, and take ownership count; add file and add
	// subfolder do not.
	exe := `C:\Program Files\s-hole\s-hole.exe`
	for _, bit := range []uint32{0x2, 0x4, 0x40, 0x10000, 0x40000, 0x80000, 0x1, 0x100} {
		pf := aclProgramFiles
		pf.acl = append(append([]ace(nil), pf.acl...), ace{mask: bit, sid: tEveryone})
		fs := map[string]objACL{
			exe:                       aclProgramFilesExe,
			`C:\Program Files\s-hole`: aclProgramFilesSub,
			`C:\Program Files`:        pf,
			`C:\`:                     aclDriveRoot,
		}
		got := evalBinary(t, exe, fs, serviceTokenSIDs(tSvcSID))
		counts := bit&(0x40|0x10000|0x40000|0x80000) != 0
		if counts && got[`C:\Program Files`] != bit {
			t.Errorf("right 0x%x on C:\\Program Files: found %v, want it reported", bit, got)
		}
		if !counts && len(got) != 0 {
			t.Errorf("right 0x%x on C:\\Program Files: found %v, want nothing", bit, got)
		}
	}
}

func TestBinaryCheck_FolderAndFileRights(t *testing.T) {
	// b/104: on the binary's folder, add file, add subfolder, delete child,
	// delete, change permissions, and take ownership count. On the binary,
	// write data, append, delete, change permissions, and take ownership
	// count; delete child means nothing on a file.
	exe := `C:\Program Files\s-hole\s-hole.exe`
	folderCounts := uint32(0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000)
	fileCounts := uint32(0x2 | 0x4 | 0x10000 | 0x40000 | 0x80000)
	for _, bit := range []uint32{0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000} {
		sub := aclProgramFilesSub
		sub.acl = append(append([]ace(nil), sub.acl...), ace{mask: bit, sid: tSvcSID})
		file := aclProgramFilesExe
		file.acl = append(append([]ace(nil), file.acl...), ace{mask: bit, sid: tSvcSID})
		for name, fs := range map[string]map[string]objACL{
			"folder": {exe: aclProgramFilesExe, `C:\Program Files\s-hole`: sub, `C:\Program Files`: aclProgramFiles, `C:\`: aclDriveRoot},
			"file":   {exe: file, `C:\Program Files\s-hole`: aclProgramFilesSub, `C:\Program Files`: aclProgramFiles, `C:\`: aclDriveRoot},
		} {
			got := evalBinary(t, exe, fs, serviceTokenSIDs(tSvcSID))
			counts, path := folderCounts, `C:\Program Files\s-hole`
			if name == "file" {
				counts, path = fileCounts, exe
			}
			if bit&counts != 0 && got[path] != bit {
				t.Errorf("right 0x%x on the %s: found %v, want it reported", bit, name, got)
			}
			if bit&counts == 0 && len(got) != 0 {
				t.Errorf("right 0x%x on the %s: found %v, want nothing", bit, name, got)
			}
		}
	}
}

func TestBinaryCheck_DenyAndNullDACL(t *testing.T) {
	// b/104: a deny entry before the allow removes the right; a deny entry
	// after it does not; a null DACL gives every right.
	exe := `C:\Program Files\s-hole\s-hole.exe`
	base := func(file objACL) map[string]objACL {
		return map[string]objACL{exe: file, `C:\Program Files\s-hole`: aclProgramFilesSub, `C:\Program Files`: aclProgramFiles, `C:\`: aclDriveRoot}
	}
	denyFirst := objACL{owner: tAdmins, acl: append([]ace{{deny: true, mask: 0x1f01ff &^ 0x1200a9, sid: tEveryone}}, ace{mask: 0x1f01ff, sid: tAuthUsers})}
	if got := evalBinary(t, exe, base(denyFirst), serviceTokenSIDs(tSvcSID)); len(got) != 0 {
		t.Errorf("deny first: found %v, want nothing", got)
	}
	denyLast := objACL{owner: tAdmins, acl: []ace{{mask: 0x1f01ff, sid: tAuthUsers}, {deny: true, mask: 0x1f01ff, sid: tEveryone}}}
	if got := evalBinary(t, exe, base(denyLast), serviceTokenSIDs(tSvcSID)); got[exe] != binaryFileWrite {
		t.Errorf("deny last: found %v, want every binary right on the file", got)
	}
	null := objACL{owner: tAdmins, null: true}
	if got := evalBinary(t, exe, base(null), serviceTokenSIDs(tSvcSID)); got[exe] != binaryFileWrite {
		t.Errorf("null DACL: found %v, want every binary right on the file", got)
	}
	// The service account as the owner gets change permissions.
	owned := objACL{owner: tSvcSID, acl: aclProgramFilesExe.acl}
	if got := evalBinary(t, exe, base(owned), serviceTokenSIDs(tSvcSID)); got[exe] != 0x40000 {
		t.Errorf("binary owned by the service: found %v, want change permissions", got)
	}
	ownedRights := objACL{owner: tSvcSID, acl: append(append([]ace(nil), aclProgramFilesExe.acl...), ace{mask: 0x20000, sid: tOwnerRights})}
	if got := evalBinary(t, exe, base(ownedRights), serviceTokenSIDs(tSvcSID)); len(got) != 0 {
		t.Errorf("binary owned by the service, OWNER RIGHTS read control: found %v, want nothing", got)
	}
}

// tEnv is the environment of a typical Windows system.
var tEnv = map[string]string{
	"SystemRoot":        `C:\Windows`,
	"ProgramFiles":      `C:\Program Files`,
	"ProgramFiles(x86)": `C:\Program Files (x86)`,
	"ProgramW6432":      `C:\Program Files`,
	"ProgramData":       `C:\ProgramData`,
	"USERPROFILE":       `C:\Users\alice`,
	"PUBLIC":            `C:\Users\Public`,
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestUnsafeConfigDir_Refused(t *testing.T) {
	// b/104: the service access list replaces the list of the folder and of
	// everything in it, so a shared folder is refused.
	for _, dir := range []string{
		`C:\`, `C:`, `D:`, `d:\`, `Z:\`,
		`C:\Windows`, `c:\windows\`, `C:\WINDOWS\System32`, `C:\Windows\Temp\s-hole`,
		`C:\Program Files`, `c:\program files\`, `C:\PROGRAM FILES`,
		`C:\Program Files (x86)`,
		`C:\ProgramData`, `c:\programdata\`,
		`C:\Users\alice`, `C:\USERS\ALICE\`,
		`C:\Users`, `c:\users\`,
	} {
		if why := unsafeConfigDir(dir, envOf(tEnv)); why == "" {
			t.Errorf("unsafeConfigDir(%q) = \"\", want a refusal", dir)
		}
	}
}

func TestUnsafeConfigDir_Allowed(t *testing.T) {
	// b/104: a folder of its own is not refused, also inside a shared
	// folder, and a name that only starts like a shared folder is not
	// refused.
	for _, dir := range []string{
		`C:\ProgramData\s-hole`, `C:\Program Files\s-hole`, `C:\Program Files (x86)\s-hole`,
		`C:\Users\alice\s-hole`, `C:\Users\Public\s-hole`, `C:\Users\Public`,
		`C:\s-hole`, `D:\s-hole`, `C:\Windows2`, `C:\WindowsApps`, `C:\ProgramDataX`,
		`C:\Users2`, `C:\Program Files2`,
	} {
		if why := unsafeConfigDir(dir, envOf(tEnv)); why != "" {
			t.Errorf("unsafeConfigDir(%q) = %q, want no refusal", dir, why)
		}
	}
}

func TestUnsafeConfigDir_EachVariable(t *testing.T) {
	// b/104: each variable refuses its own folder, read from the
	// environment and not from fixed paths.
	cases := map[string]struct{ val, dir string }{
		"SystemRoot":        {`E:\WinDir`, `E:\WinDir\Sub`},
		"ProgramFiles":      {`E:\PF`, `E:\PF`},
		"ProgramFiles(x86)": {`E:\PF86`, `E:\PF86\`},
		"ProgramW6432":      {`E:\PF64`, `e:\pf64`},
		"ProgramData":       {`E:\PD`, `E:\PD`},
		"USERPROFILE":       {`E:\Home\bob`, `E:\Home\bob`},
		"PUBLIC":            {`E:\Home\Public`, `E:\Home`},
	}
	for v, c := range cases {
		env := envOf(map[string]string{v: c.val})
		if why := unsafeConfigDir(c.dir, env); why == "" {
			t.Errorf("%s=%s: unsafeConfigDir(%q) = \"\", want a refusal", v, c.val, c.dir)
		}
		if why := unsafeConfigDir(`E:\s-hole`, env); why != "" {
			t.Errorf("%s=%s: unsafeConfigDir(E:\\s-hole) = %q, want no refusal", v, c.val, why)
		}
	}
	// PUBLIC refuses the folder above it, not PUBLIC itself.
	if why := unsafeConfigDir(`E:\Home\Public`, envOf(map[string]string{"PUBLIC": `E:\Home\Public`})); why != "" {
		t.Errorf("unsafeConfigDir(PUBLIC) = %q, want no refusal", why)
	}
}

func TestUnsafeConfigDir_EmptyEnvironment(t *testing.T) {
	// b/104: an empty variable does not refuse every path. A drive root is
	// still refused.
	empty := envOf(nil)
	for _, dir := range []string{`C:\ProgramData\s-hole`, `C:\s-hole`, `\\server\share\s-hole`} {
		if why := unsafeConfigDir(dir, empty); why != "" {
			t.Errorf("empty environment: unsafeConfigDir(%q) = %q, want no refusal", dir, why)
		}
	}
	if why := unsafeConfigDir(`C:\`, empty); why == "" {
		t.Error(`empty environment: unsafeConfigDir("C:\") = "", want a refusal`)
	}
	// A variable that holds only a backslash or a drive letter must not
	// refuse everything under it either.
	odd := envOf(map[string]string{"SystemRoot": `\`, "ProgramData": `\`, "PUBLIC": `\`, "USERPROFILE": `\`})
	if why := unsafeConfigDir(`C:\ProgramData\s-hole`, odd); why != "" {
		t.Errorf("variables set to a backslash: unsafeConfigDir = %q, want no refusal", why)
	}
}

func TestForeignItems(t *testing.T) {
	// b/104: before install, any user can add files to a config folder
	// under C:\ProgramData, and a file's owner keeps the right to change
	// its access list. foreignItems returns, sorted, each path whose owner
	// is not allowed.
	installer := tAlice
	allowed := []string{tSystem, tAdmins, tSvcSID, installer}
	const bob = "S-1-5-21-1111111111-2222222222-3333333333-1002"
	cases := []struct {
		name   string
		owners map[string]string
		want   []string
	}{
		{"nothing", nil, nil},
		{"all allowed", map[string]string{
			`C:\ProgramData\s-hole`:             tAdmins,
			`C:\ProgramData\s-hole\config.yaml`: installer,
			`C:\ProgramData\s-hole\queries.db`:  tSvcSID,
			`C:\ProgramData\s-hole\x`:           tSystem,
		}, nil},
		{"foreign at every depth, sorted", map[string]string{
			`C:\ProgramData\s-hole\z.txt`:          bob,
			`C:\ProgramData\s-hole`:                tAdmins,
			`C:\ProgramData\s-hole\a\b\c\deep.txt`: tUsers,
			`C:\ProgramData\s-hole\config.yaml`:    installer,
			`C:\ProgramData\s-hole\a`:              tTI,
			`C:\ProgramData\s-hole\m.txt`:          tEveryone,
		}, []string{
			`C:\ProgramData\s-hole\a`,
			`C:\ProgramData\s-hole\a\b\c\deep.txt`,
			`C:\ProgramData\s-hole\m.txt`,
			`C:\ProgramData\s-hole\z.txt`,
		}},
		{"the folder itself", map[string]string{`C:\ProgramData\s-hole`: bob}, []string{`C:\ProgramData\s-hole`}},
		{"no owner read is foreign", map[string]string{`C:\ProgramData\s-hole\f`: ""}, []string{`C:\ProgramData\s-hole\f`}},
		{"another service is foreign", map[string]string{`C:\ProgramData\s-hole\f`: serviceSID("other")}, []string{`C:\ProgramData\s-hole\f`}},
	}
	for _, c := range cases {
		got := foreignItems(c.owners, allowed)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: foreignItems = %q, want %q", c.name, got, c.want)
		}
	}
	// With nothing allowed, every path is foreign.
	got := foreignItems(map[string]string{`b`: tSystem, `a`: tAdmins}, nil)
	if strings.Join(got, "|") != "a|b" {
		t.Errorf("foreignItems(nothing allowed) = %q, want [a b]", got)
	}
	// The allowed list decides, not a fixed list: the installer is allowed
	// only when the caller passes it.
	got = foreignItems(map[string]string{`f`: installer}, []string{tSystem, tAdmins, tSvcSID})
	if strings.Join(got, "|") != "f" {
		t.Errorf("foreignItems(installer not allowed) = %q, want [f]", got)
	}
}
