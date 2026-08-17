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
	// /symbol is registered for GET and POST: pprof.Symbol reads program
	// counters from the URL query on GET and from the request body on POST,
	// and `go tool pprof` uses POST to symbolize (a real profile's PC list
	// does not fit in a URL). A GET-only pattern answers POST with 405 and
	// breaks remote symbolization — the whole reason to expose pprof here
	// (ultrareview bug_003). Both verbs are registered explicitly rather than
	// dropping the method prefix, because a method-less "/debug/pprof/symbol"
	// conflicts with the GET-only "/debug/pprof/" prefix under the Go 1.22 mux
	// (more specific path but more methods).
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("POST /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
}
