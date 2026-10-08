//go:build windows

package service

// Windows tests for the access lists of b/104. They run without an elevated
// prompt in a temporary folder that the test user owns. Install tests run
// only without elevation: then Install cannot reach the service manager, so a
// bug in a check cannot install a service.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// currentUserSID returns the SID of the user that runs the test.
func currentUserSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

// setDACL replaces the DACL of path with the DACL in sddlDACL.
func setDACL(t *testing.T, path, sddlDACL string) {
	t.Helper()
	if err := trySetDACL(path, sddlDACL); err != nil {
		t.Fatalf("set the DACL of %s to %s: %v", path, sddlDACL, err)
	}
}

func trySetDACL(path, sddlDACL string) error {
	sd, err := windows.SecurityDescriptorFromString(sddlDACL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// restoreAccess gives the test user full control of path again when the
// test ends, so that t.TempDir can remove it.
func restoreAccess(t *testing.T, path string) {
	t.Helper()
	me := currentUserSID(t)
	t.Cleanup(func() {
		if err := trySetDACL(path, "D:P(A;OICI;FA;;;"+me+")"); err != nil {
			t.Errorf("restore the access list of %s: %v", path, err)
		}
	})
}

// tempFile writes a file in a new temporary folder and returns its path.
func tempFile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// sortedACL returns the entries of acl as sorted strings, to compare two
// lists without their order.
func sortedACL(acl []ace) []string {
	out := make([]string, len(acl))
	for i, e := range acl {
		out[i] = fmt.Sprintf("%+v", e)
	}
	sort.Strings(out)
	return out
}

func TestReadACL_ReadsOwnerAndEntries(t *testing.T) {
	// b/104: readACL returns the owner and every allow and deny entry, with
	// its flags, mask, and SID.
	me := currentUserSID(t)
	fake := serviceSID("s-hole-test-readacl")
	p := tempFile(t, "s-hole.exe")
	restoreAccess(t, p)
	setDACL(t, p, "D:P(D;;0x10000;;;S-1-1-0)(A;;0x1f01ff;;;"+me+")(A;;0x2;;;"+fake+")")

	owner, acl, null, err := readACL(p)
	if err != nil {
		t.Fatalf("readACL = %v", err)
	}
	if owner != me && owner != tAdmins {
		t.Errorf("owner = %s, want %s or Administrators", owner, me)
	}
	if null {
		t.Error("readACL reports a null DACL, want a DACL")
	}
	want := []ace{
		{deny: true, mask: 0x10000, sid: tEveryone},
		{mask: 0x1f01ff, sid: me},
		{mask: 0x2, sid: fake},
	}
	if fmt.Sprint(acl) != fmt.Sprint(want) {
		t.Errorf("readACL entries = %+v, want %+v", acl, want)
	}
}

func TestReadACL_InheritedFlags(t *testing.T) {
	// b/104: an inherited entry keeps its inherited flag and is not read as
	// inherit-only; an inherit-only entry of a folder keeps its flag.
	me := currentUserSID(t)
	dir := t.TempDir()
	restoreAccess(t, dir)
	setDACL(t, dir, "D:P(A;OICI;FA;;;"+me+")(A;OICIIO;0x2;;;S-1-1-0)")
	_, acl, _, err := readACL(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []ace{{flags: 0x3, mask: 0x1f01ff, sid: me}, {flags: 0xb, mask: 0x2, sid: tEveryone}}
	if fmt.Sprint(acl) != fmt.Sprint(want) {
		t.Errorf("folder entries = %+v, want %+v", acl, want)
	}
	f := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, acl, _, err = readACL(f)
	if err != nil {
		t.Fatal(err)
	}
	var everyone uint32
	for _, e := range acl {
		if e.flags&0x10 == 0 {
			t.Errorf("entry %+v of a new file has no inherited flag", e)
		}
		if e.flags&0x8 != 0 {
			t.Errorf("entry %+v of a new file is inherit-only", e)
		}
		if e.sid == tEveryone {
			everyone |= e.mask
		}
	}
	if everyone != 0x2 {
		t.Errorf("Everyone has 0x%x on the new file, want the inherited 0x2", everyone)
	}
}

func TestCheckBinary_ReportsWritableFile(t *testing.T) {
	// b/104: write data for the service account on the binary is reported,
	// with the path and the name of the right.
	me := currentUserSID(t)
	fake := serviceSID("s-hole-test-writable")
	p := tempFile(t, "s-hole.exe")
	restoreAccess(t, p)
	setDACL(t, p, "D:P(A;;FA;;;"+me+")(A;;0x2;;;"+fake+")")
	err := checkBinary(p, serviceTokenSIDs(fake))
	if err == nil {
		t.Fatal("checkBinary = nil, want an error for a binary that the service can write")
	}
	if !strings.Contains(err.Error(), p+" (write or add file)") {
		t.Errorf("checkBinary = %v, want it to name %s (write or add file)", err, p)
	}
}

func TestCheckBinary_EveryoneCounts(t *testing.T) {
	// b/104: a right for Everyone reaches the service account too.
	me := currentUserSID(t)
	p := tempFile(t, "s-hole.exe")
	restoreAccess(t, p)
	setDACL(t, p, "D:P(A;;FA;;;"+me+")(A;;0x10000;;;S-1-1-0)")
	err := checkBinary(p, serviceTokenSIDs(serviceSID("s-hole-test-everyone")))
	if err == nil || !strings.Contains(err.Error(), p+" (delete)") {
		t.Errorf("checkBinary = %v, want it to name %s (delete)", err, p)
	}
}

func TestCheckBinary_ReadOnlyFileIsNotReported(t *testing.T) {
	// b/104: read and execute for the service account is not a finding. The
	// folders above the temporary folder depend on the machine, so the test
	// checks only that the file itself is not named.
	me := currentUserSID(t)
	fake := serviceSID("s-hole-test-readonly")
	p := tempFile(t, "s-hole.exe")
	restoreAccess(t, p)
	setDACL(t, p, "D:P(A;;FA;;;"+me+")(A;;0x1200a9;;;"+fake+")(A;;0x1200a9;;;S-1-1-0)")
	if err := checkBinary(p, serviceTokenSIDs(fake)); err != nil && strings.Contains(err.Error(), p+" (") {
		t.Errorf("checkBinary = %v, want the binary itself not named", err)
	}
}

func TestCheckBinary_DenyFirstRemovesRight(t *testing.T) {
	// b/104: a deny entry before the allow entry removes the right.
	me := currentUserSID(t)
	fake := serviceSID("s-hole-test-deny")
	p := tempFile(t, "s-hole.exe")
	restoreAccess(t, p)
	setDACL(t, p, "D:P(D;;0x2;;;S-1-1-0)(A;;FA;;;"+me+")(A;;0x2;;;"+fake+")")
	if err := checkBinary(p, serviceTokenSIDs(fake)); err != nil && strings.Contains(err.Error(), p+" (") {
		t.Errorf("checkBinary = %v, want the binary itself not named", err)
	}
}

func TestCheckBinary_NullDACL(t *testing.T) {
	// b/104: a null DACL gives every right to everyone.
	p := tempFile(t, "s-hole.exe")
	restoreAccess(t, p)
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatalf("set a null DACL: %v", err)
	}
	if _, _, null, err := readACL(p); err != nil || !null {
		t.Fatalf("readACL = null %v, %v, want a null DACL", null, err)
	}
	err := checkBinary(p, serviceTokenSIDs(serviceSID("s-hole-test-null")))
	if err == nil {
		t.Fatal("checkBinary = nil, want an error for a null DACL")
	}
	for _, name := range []string{"write or add file", "append or add subfolder", "delete", "change permissions", "take ownership"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("checkBinary = %v, does not name %q", err, name)
		}
	}
}

func TestCheckBinary_FailsClosed(t *testing.T) {
	// b/104: an access list that cannot be read is an error, not a pass.
	p := filepath.Join(t.TempDir(), "missing", "s-hole.exe")
	if err := checkBinary(p, serviceTokenSIDs(serviceSID("s-hole-test-missing"))); err == nil {
		t.Error("checkBinary(missing file) = nil, want an error")
	}
}

func TestRestrictDir_RoundTrip(t *testing.T) {
	// b/104: restrictDir gives the folder the protected service access
	// list, and a file and a folder that were already in it inherit read
	// and execute for the service, and no write right.
	fake := serviceSID("s-hole-test-restrict")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("dns: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	restoreAccess(t, dir)
	if err := restrictDir(dir, fake); err != nil {
		if !windows.GetCurrentProcessToken().IsElevated() {
			t.Skipf("restrictDir = %v; run this test from an elevated prompt", err)
		}
		t.Fatalf("restrictDir = %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if ctl, _, err := sd.Control(); err != nil || ctl&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("folder control = 0x%x, %v, want a protected DACL", ctl, err)
	}
	_, acl, null, err := readACL(dir)
	if err != nil || null {
		t.Fatalf("readACL(folder) = null %v, %v", null, err)
	}
	if got, want := sortedACL(acl), sortedACL(serviceDirACL(fake)); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("folder entries = %v, want %v", got, want)
	}

	svc := serviceTokenSIDs(fake)
	for _, p := range []string{cfg, sub} {
		owner, acl, null, err := readACL(p)
		if err != nil || null {
			t.Fatalf("readACL(%s) = null %v, %v", p, null, err)
		}
		got := grantedRights(owner, acl, null, svc)
		if got&tWriteLike != 0 {
			t.Errorf("%s: the service gets 0x%x (%s), want no write right", filepath.Base(p), got&tWriteLike, rightNames(got))
		}
		if got&0x1200a9 != 0x1200a9 {
			t.Errorf("%s: the service gets 0x%x, want read and execute", filepath.Base(p), got)
		}
		for _, e := range acl {
			if e.sid != tSystem && e.sid != tAdmins && e.sid != fake && e.sid != owner && e.sid != tCreatorOwner {
				t.Errorf("%s: entry for SID %s, want only SYSTEM, Administrators, the service, and the owner", filepath.Base(p), e.sid)
			}
		}
	}
}

func TestInstall_RefusesBeforeAnyChange(t *testing.T) {
	// b/104: Install checks everything before the first change. Without
	// elevation it cannot reach the service manager, so an error that names
	// the service manager means that a check did not refuse.
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("elevated: a missing check could install a service; run without elevation")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exeDir := filepath.Dir(exe)
	inExeDir := filepath.Join(exeDir, "config.yaml")
	if err := os.WriteFile(inExeDir, []byte("dns: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(inExeDir) })

	before := dirSDDL(t, exeDir)
	cases := map[string]string{
		"missing config":            filepath.Join(t.TempDir(), "missing.yaml"),
		"config is a folder":        t.TempDir(),
		"binary in config folder":   inExeDir,
		"binary in folder, as case": strings.ToUpper(exeDir) + `\config.yaml`,
	}
	if root := os.Getenv("SystemRoot"); root != "" {
		if _, err := os.Stat(filepath.Join(root, "win.ini")); err == nil {
			cases["config in the Windows folder"] = filepath.Join(root, "win.ini")
		}
	}
	for name, cfg := range cases {
		err := Install(cfg)
		if err == nil {
			t.Errorf("%s: Install(%s) = nil, want a refusal", name, cfg)
			continue
		}
		if strings.Contains(err.Error(), "SCM") || strings.Contains(err.Error(), "create service") {
			t.Errorf("%s: Install(%s) = %v, want a refusal before the service manager", name, cfg, err)
		}
	}
	if after := dirSDDL(t, exeDir); after != before {
		t.Errorf("the access list of %s changed:\n before %s\n after  %s", exeDir, before, after)
	}
}

// dirSDDL returns the DACL of path as SDDL.
func dirSDDL(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// ownerDir makes a config folder with a file, a subfolder, and a file two
// levels down, all owned by the test user. It returns the folder and the
// deep file.
func ownerDir(t *testing.T) (dir, deep string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("dns: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	deep = filepath.Join(sub, "deep.txt")
	if err := os.WriteFile(deep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, deep
}

// setOwnerOrSkip makes sid the owner of path, or skips the test: setting an
// owner other than the test user needs SeRestorePrivilege, which only an
// elevated prompt has. The privilege is turned on for the test only.
func setOwnerOrSkip(t *testing.T, path, sid string) {
	t.Helper()
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		t.Skipf("cannot open the process token: %v", err)
	}
	defer tok.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeRestorePrivilege"), &luid); err != nil {
		t.Skipf("cannot look up SeRestorePrivilege: %v", err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err == nil {
		t.Cleanup(func() {
			var tok2 windows.Token
			if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES, &tok2) == nil {
				off := windows.Tokenprivileges{PrivilegeCount: 1}
				off.Privileges[0] = windows.LUIDAndAttributes{Luid: luid}
				_ = windows.AdjustTokenPrivileges(tok2, false, &off, 0, nil, nil)
				tok2.Close()
			}
		})
	}
	s, err := windows.StringToSid(sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, s, nil, nil, nil); err != nil {
		t.Skipf("cannot set the owner of %s to %s without SeRestorePrivilege (run from an elevated prompt): %v", path, sid, err)
	}
	if owner, _, _, err := readACL(path); err != nil || owner != sid {
		t.Fatalf("owner of %s = %s, %v, want %s", path, owner, err, sid)
	}
}

func TestCheckOwners_OwnFilesPass(t *testing.T) {
	// b/104: a config folder that holds only items that the account that
	// runs the install owns passes.
	dir, _ := ownerDir(t)
	if err := checkOwners(dir, serviceSID("s-hole-test-owners")); err != nil {
		t.Errorf("checkOwners = %v, want nil", err)
	}
}

func TestCheckOwners_AllowedOwnersPass(t *testing.T) {
	// b/104: SYSTEM, Administrators, and the service may own items.
	fake := serviceSID("s-hole-test-allowed")
	for _, sid := range []string{tSystem, tAdmins, fake} {
		dir, deep := ownerDir(t)
		setOwnerOrSkip(t, deep, sid)
		if err := checkOwners(dir, fake); err != nil {
			t.Errorf("owner %s: checkOwners = %v, want nil", sid, err)
		}
	}
}

func TestCheckOwners_ForeignOwnerAtAnyDepth(t *testing.T) {
	// b/104: an item that another account owns, at any depth, is refused,
	// and the error names it. So is the folder itself.
	fake := serviceSID("s-hole-test-foreign")
	dir, deep := ownerDir(t)
	setOwnerOrSkip(t, deep, tUsers)
	err := checkOwners(dir, fake)
	if err == nil || !strings.Contains(err.Error(), deep) {
		t.Errorf("checkOwners = %v, want an error that names %s", err, deep)
	}
	if err != nil && strings.Contains(err.Error(), filepath.Join(dir, "config.yaml")) {
		t.Errorf("checkOwners = %v names config.yaml, which the test user owns", err)
	}

	dir2, _ := ownerDir(t)
	setOwnerOrSkip(t, dir2, tUsers)
	if err := checkOwners(dir2, fake); err == nil || !strings.Contains(err.Error(), dir2) {
		t.Errorf("checkOwners(folder owned by Users) = %v, want an error that names %s", err, dir2)
	}
}

func TestCheckOwners_ServiceSIDIsTheOneAllowed(t *testing.T) {
	// b/104: the service SID that the caller passes is allowed; the SID of
	// another service is not.
	dir, deep := ownerDir(t)
	setOwnerOrSkip(t, deep, serviceSID("s-hole-test-other"))
	if err := checkOwners(dir, serviceSID("s-hole-test-this")); err == nil || !strings.Contains(err.Error(), deep) {
		t.Errorf("checkOwners = %v, want an error that names %s", err, deep)
	}
}

func TestCheckOwners_RefusesJunction(t *testing.T) {
	// b/104: a junction in the config folder is refused, and the error
	// names it. A junction needs no privilege.
	dir, _ := ownerDir(t)
	target := t.TempDir()
	link := filepath.Join(dir, "a", "j")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot make a junction: %v: %s", err, out)
	}
	err := checkOwners(dir, serviceSID("s-hole-test-junction"))
	if err == nil || !strings.Contains(err.Error(), link) {
		t.Errorf("checkOwners = %v, want an error that names the junction %s", err, link)
	}
}

func TestCheckOwners_RefusesSymlink(t *testing.T) {
	// b/104: a symbolic link in the config folder is refused, and the error
	// names it.
	dir, deep := ownerDir(t)
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(deep, link); err != nil {
		t.Skipf("cannot make a symbolic link here (needs a privilege or developer mode): %v", err)
	}
	err := checkOwners(dir, serviceSID("s-hole-test-symlink"))
	if err == nil || !strings.Contains(err.Error(), link) {
		t.Errorf("checkOwners = %v, want an error that names the link %s", err, link)
	}
}

func TestCheckOwners_MissingFolderFails(t *testing.T) {
	// b/104: a folder that cannot be read is an error, not a pass.
	if err := checkOwners(filepath.Join(t.TempDir(), "missing"), serviceSID("s-hole-test-missing")); err == nil {
		t.Error("checkOwners(missing folder) = nil, want an error")
	}
}
