//go:build windows

// Package service integrates s-hole with the Windows Service Control
// Manager (SCM). It exposes install/uninstall/start/stop subcommands and
// the in-process SCM event loop. A no-op stub for non-Windows targets
// lives in svc_other.go so main.go can call into the package without
// build tags.
package service

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcName = "s-hole"
	svcDesc = "Network-level DNS sinkhole for ad blocking."
)

// IsWindowsService reports whether the process was launched by the Windows SCM.
func IsWindowsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

// Run starts fn in a goroutine and blocks in the Windows SCM event loop.
// stop is called when the SCM sends a Stop or Shutdown control code.
func Run(fn, stop func()) error {
	return svc.Run(svcName, &handler{fn: fn, stop: stop})
}

type handler struct {
	fn   func()
	stop func()
}

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	go h.fn()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			s <- svc.Status{State: svc.StopPending}
			h.stop() // calls os.Exit(0); process exits before Execute returns
		}
	}
	return false, 0
}

// Install registers the binary as an auto-start Windows Service.
// configPath must be an absolute path.
func Install(configPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists; run -service uninstall first", svcName)
	}

	s, err := m.CreateService(svcName, exePath, mgr.Config{
		DisplayName: "s-hole DNS Sinkhole",
		Description: svcDesc,
		StartType:   mgr.StartAutomatic,
	}, "-config", configPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	s.Close()
	fmt.Printf("service %q installed (auto-start)\n  binary: %s\n  config: %s\n", svcName, exePath, configPath)
	return nil
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
