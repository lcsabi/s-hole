package api

import (
	"net/http"
	"net/http/pprof"
)

// registerPprof attaches the standard net/http/pprof handlers to mux
// under /debug/pprof/. Off by default; the Server.enablePprof flag
// controls whether handler() calls this — see R35.
//
// Only enable when the admin server is bound to localhost. pprof reveals
// goroutine stacks, heap layouts, and binary symbols — useful for
// incident response, dangerous if exposed to the LAN.
func registerPprof(mux *http.ServeMux) {
	// The pprof.Index handler dispatches on the trailing path component,
	// so a single Handle on the directory prefix covers /heap, /goroutine,
	// /allocs, /block, /mutex, /threadcreate, plus the index page.
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
}
