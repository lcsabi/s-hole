//go:build windows

// Package service integrates s-hole with the Windows Service Control
// Manager (SCM). It exposes install/uninstall/start/stop subcommands and
// the in-process SCM event loop. A no-op stub for non-Windows targets
// lives in svc_other.go so cmd/s-hole/main.go can call into the package without
// build tags.
package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcName = "s-hole"
	svcDesc = "Network-level DNS sinkhole for ad blocking."
	// svcAccount is the service's virtual account. Windows creates it with
	// the service and gives it no rights beyond its own; without it, the
	// service ran as LocalSystem, the most powerful account on the machine
	// (b/086). Binding port 53 needs no special right on Windows.
	svcAccount = `NT SERVICE\` + svcName
)

// IsWindowsService reports whether the process was launched by the Windows SCM.
func IsWindowsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

// exitServeFailed is the service-specific exit code that s-hole reports to
// the SCM when the DNS server stops without a stop request. A non-zero code
// makes the SCM apply the recovery actions that Install sets.
const exitServeFailed = 1

// stopWaitHint tells the SCM how long the StopPending state can last, in
// milliseconds. main's teardown gives the admin HTTP drain and the reload wait
// 5 s each, and then flushes the query log. Without a hint, the SCM gets no
// estimate for a stop that can take more than 10 s.
const stopWaitHint = 15000

// Run starts fn (the DNS server) in a goroutine and blocks in the Windows SCM
// event loop. stop (the ordered teardown) is called when the SCM sends a
// Stop or Shutdown control code, or when fn returns first.
func Run(fn func() error, stop func()) error {
	return svc.Run(svcName, &handler{fn: fn, stop: stop})
}

type handler struct {
	fn   func() error
	stop func()
}

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	served := make(chan error, 1)
	go func() { served <- h.fn() }()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending, WaitHint: stopWaitHint}
				// doStop runs the ordered teardown and returns; it no longer
				// calls os.Exit (b/043). Report Stopped so the SCM does not
				// hang in StopPending, then return. After Execute returns,
				// svc.Run returns and main exits (b/044).
				h.stop()
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case err := <-served:
			// The DNS server stopped without an SCM stop request, so the
			// service answers no queries. Before, the service still reported
			// Running (b/065). Run the teardown (a no-op if it already ran).
			s <- svc.Status{State: svc.StopPending, WaitHint: stopWaitHint}
			h.stop()
			if err == nil {
				// Only Shutdown makes Start return nil, so doStop already ran
				// outside the SCM loop: Go can deliver a Windows shutdown
				// event to main's signal handler as SIGTERM. A clean stop.
				return false, 0
			}
			// Return a failure code: svc.Run reports Stopped with it, and the
			// SCM restarts the service through the recovery actions that
			// Install sets.
			return true, exitServeFailed
		}
	}
}

// Install registers the binary as an auto-start Windows Service.
// configPath must be an absolute path. Install refuses when the service
// account could change or replace the binary (b/104): an administrator who
// later runs that binary (-purge, -service uninstall) would run code that
// the service wrote. Put the binary in C:\Program Files\s-hole and the config
// in a folder of its own, such as C:\ProgramData\s-hole.
func Install(configPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return err
	}

	// Check the config path, the config folder, and the binary before the
	// first change, so these refusals change nothing. The owner check runs
	// after restrictDir (below), and its refusal keeps the new access list.
	if fi, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("config file: %w", err)
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("config file %s is not a regular file", configPath)
	}
	configDir := filepath.Dir(configPath)
	if why := unsafeConfigDir(configDir, os.Getenv); why != "" {
		return fmt.Errorf("config folder %s cannot get the service access list: %s. Put config.yaml in a folder of its own, such as C:\\ProgramData\\s-hole", configDir, why)
	}
	if strings.EqualFold(filepath.Dir(exePath), configDir) {
		return fmt.Errorf("s-hole.exe is in the config folder %s, where the service can add files. Put s-hole.exe in C:\\Program Files\\s-hole", configDir)
	}
	sid := serviceSID(svcName)
	if err := checkBinary(exePath, serviceTokenSIDs(sid)); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists. Run -service uninstall first", svcName)
	}

	// The service runs in the config file's directory (b/066), so its data
	// files land there. Give that folder the service access list before the
	// service exists. Without it, the query history inherits the access list
	// of the parent folder: under C:\ProgramData every user can read it, and
	// under C:\ every signed-in user can also change it (b/076). The list
	// names the service by its SID, which Windows accepts before the account
	// exists. A failure stops the install, so the service never runs in a
	// folder that other users can read.
	if err := restrictDir(configDir, sid); err != nil {
		return fmt.Errorf("set the access list of %s: %w", configDir, err)
	}
	// From here on, other accounts cannot add files to the folder. Check
	// that none put a file or a link there before (b/104).
	if err := checkOwners(configDir, sid); err != nil {
		return err
	}

	s, err := m.CreateService(svcName, exePath, mgr.Config{
		DisplayName:      "s-hole DNS Sinkhole",
		Description:      svcDesc,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: svcAccount,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "-config", configPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	// Restart the service when it fails, like Restart=on-failure in the
	// systemd unit. By default the SCM applies recovery actions only when
	// the process crashes; the non-crash flag also applies them when the
	// service stops with a non-zero exit code, which is how Execute reports
	// a DNS server failure (b/065). The service runs without these actions,
	// so a failure to set them is a warning, not a failed install.
	if err := setRecovery(s); err != nil {
		fmt.Printf("warning: could not set restart-on-failure for service %q: %v\n", svcName, err)
	}
	s.Close()

	// Register an event-log source so Event Viewer renders s-hole's messages
	// without the "description cannot be found" preamble. The service still
	// runs and logs without this (against the default application source), so
	// a registration failure is a warning, not a fatal install error. An
	// already-registered source (a reinstall) is not an error.
	if err := eventlog.InstallAsEventCreate(svcName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		fmt.Printf("warning: could not register event-log source %q: %v\n", svcName, err)
	}

	fmt.Printf("service %q installed (auto-start, runs as %s)\n"+
		"  binary: %s (the service account cannot change it)\n"+
		"  config: %s (the service reads this folder and changes only the files that it creates: edit config.yaml as an administrator)\n",
		svcName, svcAccount, exePath, configPath)
	return nil
}

// restrictDir replaces the access list of dir with serviceDirACL for the
// service SID sid, and blocks inheritance from the parent. SYSTEM and the
// Administrators group get full control; the service account gets read and
// execute on everything, "add file" and "add subfolder" on dir itself, and
// full control only of the files and folders that it creates (CREATOR
// OWNER).
// SetNamedSecurityInfo also gives the new inherited entries to the files and
// folders that are already in dir.
func restrictDir(dir, sid string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl(serviceDirACL(sid)))
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// checkBinary returns an error that names each path through which the
// holder of sids could change or replace the binary at exe (see
// binaryPaths). An access list that it cannot read is an error too, so the
// check fails closed.
func checkBinary(exe string, sids []string) error {
	var found []string
	for _, c := range binaryPaths(exe) {
		owner, acl, nullDACL, err := readACL(c.path)
		if err != nil {
			return fmt.Errorf("read the access list of %s: %w", c.path, err)
		}
		if got := grantedRights(owner, acl, nullDACL, sids) & c.rights; got != 0 {
			found = append(found, fmt.Sprintf("%s (%s)", c.path, rightNames(got)))
		}
	}
	if len(found) > 0 {
		return fmt.Errorf("the service account %s could change or replace %s through: %s. Put s-hole.exe in C:\\Program Files\\s-hole and run -service install from there",
			svcAccount, exe, strings.Join(found, "; "))
	}
	return nil
}

// checkOwners returns an error that names each file and folder in dir
// (dir included) whose owner is not SYSTEM, the Administrators group, the
// service, or the account that runs the install, and each link or other
// item that is not a file or a folder. A link could point the service and the
// purge at a file outside the folder.
func checkOwners(dir, svcSID string) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read the account that runs the install: %w", err)
	}
	allowed := []string{sidSystem, sidAdministrators, svcSID, u.User.Sid.String()}
	owners := make(map[string]string)
	var links []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			links = append(links, p)
			return nil
		}
		owner, _, _, err := readACL(p)
		if err != nil {
			return fmt.Errorf("read the owner of %s: %w", p, err)
		}
		owners[p] = owner
		return nil
	})
	if err != nil {
		return err
	}
	found := links
	found = append(found, foreignItems(owners, allowed)...)
	if len(found) > 0 {
		return fmt.Errorf("the config folder %s holds items that another account owns, or links: %s. Delete them, then run -service install again",
			dir, strings.Join(found, "; "))
	}
	return nil
}

// The callback entry types carry a condition. checkBinary counts an allow
// entry with a condition as if the condition were true, and skips a deny
// entry with a condition, so it can only report too much.
const (
	accessAllowedCallbackACEType = 0x9
)

// readACL reads the owner and the DACL of path. A missing or NULL DACL
// (nullDACL) allows everything; an empty DACL allows nothing. Entries of
// other types (audit, object) are not part of a file's access check and are
// skipped.
func readACL(path string) (owner string, acl []ace, nullDACL bool, err error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", nil, false, err
	}
	o, _, err := sd.Owner()
	if err != nil {
		return "", nil, false, err
	}
	if o != nil {
		owner = o.String()
	}
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		return owner, nil, true, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &a); err != nil {
			return "", nil, false, err
		}
		var deny bool
		switch a.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, accessAllowedCallbackACEType:
		case windows.ACCESS_DENIED_ACE_TYPE:
			deny = true
		default:
			continue
		}
		// The SID starts at SidStart in every entry of these types.
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		acl = append(acl, ace{deny: deny, flags: a.Header.AceFlags, mask: uint32(a.Mask), sid: sid.String()})
	}
	return owner, acl, false, nil
}

// recoveryResetSeconds is the time without a failure after which the SCM
// resets its failure count, so the next failure starts again at the first
// action.
const recoveryResetSeconds = 24 * 60 * 60

// setRecovery sets three restart actions, 5 seconds apart like the systemd
// unit's RestartSec, and turns them on for a non-zero exit code.
func setRecovery(s *mgr.Service) error {
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, recoveryResetSeconds); err != nil {
		return err
	}
	return s.SetRecoveryActionsOnNonCrashFailures(true)
}

// Uninstall removes the Windows Service registration.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", svcName, err)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	// Deregister the event-log source registered by Install. A missing source
	// (never registered, or a partial install) is not an error, so removal
	// stays idempotent.
	if err := eventlog.Remove(svcName); err != nil && !strings.Contains(err.Error(), "cannot find") {
		fmt.Printf("warning: could not remove event-log source %q: %v\n", svcName, err)
	}

	fmt.Printf("service %q uninstalled\n", svcName)
	return nil
}

// Start asks the SCM to start the service.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", svcName, err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Printf("service %q started\n", svcName)
	return nil
}

// Stop sends a stop control to the running service.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", svcName, err)
	}
	defer s.Close()

	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	fmt.Printf("service %q stop requested\n", svcName)
	return nil
}
