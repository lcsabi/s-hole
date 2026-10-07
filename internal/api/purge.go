package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// PurgeStep is one part of a purge: what was deleted and what happened.
type PurgeStep struct {
	What   string `json:"what"`
	Result string `json:"result"`
	Failed bool   `json:"failed,omitempty"`
}

// PurgeReport is the reply to POST /api/purge and the summary that
// `s-hole -purge` prints.
type PurgeReport struct {
	Steps []PurgeStep `json:"steps"`
}

// Failed reports whether any step failed.
func (r PurgeReport) Failed() bool {
	for _, s := range r.Steps {
		if s.Failed {
			return true
		}
	}
	return false
}

// SetPurge wires the purge function. main builds it, because main owns every
// store a purge must reach. Call before Serve; without it POST /api/purge
// answers 503.
func (s *Server) SetPurge(fn func(context.Context) PurgeReport) {
	s.purgeFn = fn
}

// purgeTimeout bounds one purge. VACUUM rewrites the database file, which
// takes a few seconds for a large history on an SD card.
const purgeTimeout = 25 * time.Second

// handlePurge deletes the query history and everything else s-hole wrote
// (see main's purge function). It is the most destructive request the API
// has, so it is accepted only from this machine: from a loopback address or
// one of the host's own addresses. A device on the LAN cannot wipe the
// history, which keeps the history useful as a record. On the host, the
// dashboard button and `s-hole -purge` both reach it. The body must be the
// JSON {"confirm": true}, so a stray POST does nothing.
func (s *Server) handlePurge(w http.ResponseWriter, r *http.Request) {
	if !fromThisMachine(r.RemoteAddr) {
		http.Error(w, "the query history can be deleted only from the s-hole host: open the dashboard there, or run `s-hole -purge` (in Docker: docker exec <container> s-hole -purge)", http.StatusForbidden)
		return
	}
	if !isJSON(r) {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var body struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !body.Confirm {
		http.Error(w, `invalid body: expected {"confirm": true}`, http.StatusBadRequest)
		return
	}
	if s.purgeFn == nil {
		http.Error(w, "purge is not available", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), purgeTimeout)
	defer cancel()
	rep := s.purgeFn(ctx)
	logger.Info("query history purged via API", "steps", len(rep.Steps), "failed", rep.Failed())
	if rep.Failed() {
		w.WriteHeader(http.StatusInternalServerError)
	}
	writeJSON(w, rep)
}

// fromThisMachine reports whether remoteAddr is a loopback address or one of
// this host's own interface addresses.
func fromThisMachine(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap().WithZone("")
	if ip.IsLoopback() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if own, ok := netip.AddrFromSlice(n.IP); ok && own.Unmap() == ip {
				return true
			}
		}
	}
	return false
}
