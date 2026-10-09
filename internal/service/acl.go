package service

// The access-list rules for the Windows service. This file has no build tag:
// the rules are plain data and arithmetic, so the tests run on Linux too. Only
// svc_windows.go reads and writes real access lists.

import (
	"crypto/sha1" //nolint:gosec // G505: the service SID is defined by SHA-1; it is not a security hash here
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
)

// Windows access rights for files and folders. A folder uses the same bits
// with other names: 0x2 is "add file", 0x4 is "add subfolder".
const (
	rightReadData        = 0x1
	rightWriteData       = 0x2 // on a folder: add file
	rightAppendData      = 0x4 // on a folder: add subfolder
	rightReadEA          = 0x8
	rightWriteEA         = 0x10
	rightExecute         = 0x20 // on a folder: traverse
	rightDeleteChild     = 0x40
	rightReadAttributes  = 0x80
	rightWriteAttributes = 0x100
	rightDelete          = 0x10000
	rightReadControl     = 0x20000
	rightWriteDAC        = 0x40000
	rightWriteOwner      = 0x80000
	rightSynchronize     = 0x100000

	genericAll     = 0x10000000
	genericExecute = 0x20000000
	genericWrite   = 0x40000000
	genericRead    = 0x80000000

	fileGenericRead = rightReadControl | rightReadData | rightReadAttributes |
		rightReadEA | rightSynchronize // 0x120089
	fileGenericWrite = rightReadControl | rightWriteData | rightWriteAttributes |
		rightWriteEA | rightAppendData | rightSynchronize // 0x120116
	fileGenericExecute = rightReadControl | rightReadAttributes | rightExecute |
		rightSynchronize // 0x1200a0
	fileAllAccess = 0x1f01ff

	// rightReadExecute is "read and execute" (icacls RX).
	rightReadExecute = fileGenericRead | fileGenericExecute // 0x1200a9
)

// The rights that let the service account change or replace the binary. On
// the binary file: change its content, delete or rename it, or change its
// access list or owner. On the binary's folder: also add a file (such as a
// DLL that Windows loads from the program folder) or a subfolder, or delete
// a file in it. On a folder above it: rename or delete the path to the
// binary, or change its access list or owner.
const (
	binaryFileWrite   = rightWriteData | rightAppendData | rightDelete | rightWriteDAC | rightWriteOwner
	binaryFolderWrite = rightWriteData | rightAppendData | rightDeleteChild | rightDelete | rightWriteDAC | rightWriteOwner
	parentFolderWrite = rightDeleteChild | rightDelete | rightWriteDAC | rightWriteOwner
)

// ACE flags.
const (
	aceObjectInherit    = 0x1
	aceContainerInherit = 0x2
	aceInheritOnly      = 0x8
)

// Well-known SIDs.
const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	sidCreatorOwner   = "S-1-3-0"
	sidOwnerRights    = "S-1-3-4"
)

// ace is one entry of an access list: allow or deny mask to sid.
type ace struct {
	deny  bool
	flags uint8
	mask  uint32
	sid   string
}

// serviceSID returns the SID of the virtual account NT SERVICE\<name>:
// S-1-5-80 followed by the SHA-1 of the upper-case name in UTF-16LE, read as
// five little-endian 32-bit numbers. Windows derives it the same way, so
// s-hole knows the SID before the service exists.
func serviceSID(name string) string {
	u := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	sum := sha1.Sum(b) //nolint:gosec // G401: see the import
	parts := make([]string, 5)
	for i := range parts {
		parts[i] = fmt.Sprint(binary.LittleEndian.Uint32(sum[4*i:]))
	}
	return "S-1-5-80-" + strings.Join(parts, "-")
}

// serviceTokenSIDs returns the SIDs that grant rights to the service: the
// service's own SID and the groups that Windows puts in the token of a
// service that runs as a virtual account (whoami /groups as the service
// account on Windows 10). An extra group here only makes the binary check
// stricter.
func serviceTokenSIDs(svcSID string) []string {
	return []string{
		svcSID,
		"S-1-1-0",      // Everyone
		"S-1-2-0",      // LOCAL
		"S-1-2-1",      // CONSOLE LOGON
		"S-1-5-6",      // NT AUTHORITY\SERVICE
		"S-1-5-11",     // NT AUTHORITY\Authenticated Users
		"S-1-5-15",     // NT AUTHORITY\This Organization
		"S-1-5-32-545", // BUILTIN\Users
		"S-1-5-80-0",   // NT SERVICE\ALL SERVICES
	}
}

// serviceDirACL is the access list that -service install gives the config
// folder. SYSTEM and the Administrators group get full control. The service
// account gets read and execute on the folder and on everything in it, and
// on the folder itself (not inherited) the rights to add a file and a
// subfolder. CREATOR OWNER gives the owner of each new file or subfolder full
// control of it. So the service can create its data files and change or
// delete them, but it cannot change config.yaml or another file that an
// administrator put in the folder.
func serviceDirACL(svcSID string) []ace {
	const inherit = aceObjectInherit | aceContainerInherit
	return []ace{
		{flags: inherit, mask: fileAllAccess, sid: sidSystem},
		{flags: inherit, mask: fileAllAccess, sid: sidAdministrators},
		{flags: inherit, mask: rightReadExecute, sid: svcSID},
		{flags: 0, mask: rightWriteData | rightAppendData, sid: svcSID},
		{flags: inherit | aceInheritOnly, mask: fileAllAccess, sid: sidCreatorOwner},
	}
}

// sddl returns acl as a protected DACL in the Security Descriptor Definition
// Language: "D:P" blocks the entries of the parent folder.
func sddl(acl []ace) string {
	var b strings.Builder
	b.WriteString("D:P")
	for _, e := range acl {
		typ := "A"
		if e.deny {
			typ = "D"
		}
		var fl string
		if e.flags&aceObjectInherit != 0 {
			fl += "OI"
		}
		if e.flags&aceContainerInherit != 0 {
			fl += "CI"
		}
		if e.flags&aceInheritOnly != 0 {
			fl += "IO"
		}
		fmt.Fprintf(&b, "(%s;%s;0x%x;;;%s)", typ, fl, e.mask, e.sid)
	}
	return b.String()
}

// mapGeneric replaces the generic rights in mask with the file rights that
// they stand for.
func mapGeneric(mask uint32) uint32 {
	m := mask &^ (genericAll | genericExecute | genericWrite | genericRead)
	if mask&genericRead != 0 {
		m |= fileGenericRead
	}
	if mask&genericWrite != 0 {
		m |= fileGenericWrite
	}
	if mask&genericExecute != 0 {
		m |= fileGenericExecute
	}
	if mask&genericAll != 0 {
		m |= fileAllAccess
	}
	return m
}

// grantedRights returns the rights that the holder of sids gets on an object
// with this owner and access list, as the Windows access check computes
// them: the entries apply in order, and a right that an earlier entry denies
// stays denied. Inherit-only entries do not apply to the object. A nil DACL
// (nullDACL) allows everything. The owner implicitly has read-control and
// write-DAC, unless the list has an entry for OWNER RIGHTS. Privileges and
// integrity labels are not part of the result.
func grantedRights(owner string, acl []ace, nullDACL bool, sids []string) uint32 {
	if nullDACL {
		return fileAllAccess
	}
	holds := make(map[string]bool, len(sids)+1)
	for _, s := range sids {
		holds[s] = true
	}
	isOwner := holds[owner]
	ownerRightsSet := false
	if isOwner {
		holds[sidOwnerRights] = true
	}
	var granted, denied uint32
	for _, e := range acl {
		if e.flags&aceInheritOnly != 0 {
			continue
		}
		if e.sid == sidOwnerRights {
			ownerRightsSet = true
		}
		if !holds[e.sid] {
			continue
		}
		m := mapGeneric(e.mask)
		if e.deny {
			denied |= m &^ granted
		} else {
			granted |= m &^ denied
		}
	}
	if isOwner && !ownerRightsSet {
		granted |= rightReadControl | rightWriteDAC
	}
	return granted
}

// pathCheck is a path and the rights that the service account must not have
// on it.
type pathCheck struct {
	path   string
	rights uint32
}

// binaryPaths returns the checks for the binary at exe (a clean absolute
// Windows path): the file, its folder, and every folder above it up to the
// drive root or the share.
func binaryPaths(exe string) []pathCheck {
	checks := []pathCheck{{exe, binaryFileWrite}}
	rights := uint32(binaryFolderWrite)
	for p := exe; ; {
		i := strings.LastIndexByte(p, '\\')
		if i <= 0 {
			break
		}
		p = p[:i]
		if len(p) == 2 && p[1] == ':' {
			checks = append(checks, pathCheck{p + `\`, rights})
			break
		}
		if strings.HasPrefix(p, `\\`) && !strings.Contains(p[2:], `\`) {
			break // \\server is not a folder
		}
		checks = append(checks, pathCheck{p, rights})
		rights = parentFolderWrite
	}
	return checks
}

// rightNames names the rights in mask for an error message.
func rightNames(mask uint32) string {
	names := []struct {
		bit  uint32
		name string
	}{
		{rightWriteData, "write or add file"},
		{rightAppendData, "append or add subfolder"},
		{rightDeleteChild, "delete child"},
		{rightDelete, "delete"},
		{rightWriteDAC, "change permissions"},
		{rightWriteOwner, "take ownership"},
	}
	var out []string
	for _, n := range names {
		if mask&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return strings.Join(out, ", ")
}

// unsafeConfigDir returns why dir must not get the service access list, or
// "" when it can. The access list also applies to everything in the folder,
// so on a shared folder other programs and users would lose access: a drive
// root, the Windows folder or a folder in it, Program Files, ProgramData, the
// user's profile folder, or the folder that holds the profiles. dir is a
// clean absolute Windows path; getenv reads the environment.
func unsafeConfigDir(dir string, getenv func(string) string) string {
	norm := func(p string) string { return strings.ToLower(strings.TrimRight(p, `\`)) }
	d := norm(dir)
	if len(d) == 2 && d[1] == ':' {
		return "it is the root of a drive"
	}
	if root := norm(getenv("SystemRoot")); root != "" && (d == root || strings.HasPrefix(d, root+`\`)) {
		return "it is in the Windows folder"
	}
	shared := []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "USERPROFILE"}
	for _, v := range shared {
		if p := norm(getenv(v)); p != "" && d == p {
			return "it is the " + v + " folder"
		}
	}
	if pub := norm(getenv("PUBLIC")); pub != "" {
		if i := strings.LastIndexByte(pub, '\\'); i > 0 && d == pub[:i] {
			return "it is the folder that holds the user profiles"
		}
	}
	return ""
}

// foreignItems returns, sorted, each path in owners (path to owner SID) whose
// owner is not one of allowed. Before install, the config folder has the
// access list of its parent; under ProgramData every user can add files to
// it. The owner of a file keeps the right to change its access list, so a
// file that another account put there before the install stays under that
// account's control.
func foreignItems(owners map[string]string, allowed []string) []string {
	ok := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		ok[a] = true
	}
	var out []string
	for p, o := range owners {
		if !ok[o] {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
