// Package privacylint checks the source code of s-hole against the privacy
// rules in the "Privacy first" section of CLAUDE.md. A behavior test pins the
// code that exists. This lint pins a rule, so it also covers code that is
// written later. TestRepository runs it under `make test`, so it runs in
// `make check` and in CI; `make privacy-lint` runs it alone.
//
// # How it works
//
// The lint runs `go list -deps -export` and type-checks each package of the
// module from source with go/types, once for the host GOOS and once for
// Windows (on a Windows host, for Windows only). Imports come from the export
// data that the go command keeps in its build cache, so the lint adds no
// dependency. The go command runs with -mod=readonly: it does not change
// go.mod or go.sum. If the module cache does not have a module that a build
// needs (for example a module that only the Windows build uses), the go
// command downloads it, as go test does, and go.sum checks it. Test files are
// not checked: tests use query names and addresses on purpose.
//
// The rules use the type information to match a function, a variable, or a
// type by its full name, such as "net/http.Get" or "(*net/http.Client).Do",
// not by how the code spells it. client-address matches a RemoteAddr()
// net.Addr method by its signature, so it covers every type with that method;
// metric-labels reads string literals.
//
// # Rules
//
//   - client-address: a read of a client address: a RemoteAddr method (as on
//     dns.ResponseWriter and net.Conn), the RemoteAddr field of an
//     http.Request, or a call of a function that a //privacy:source
//     client-address comment marks. A type assertion that keeps only the type
//     reads no address.
//   - outbound: a call, a package variable, or a value of a type that can open
//     an outbound connection, look up a name through the system resolver, or
//     start a program.
//   - server-errorlog: an http.Server whose ErrorLog is not newErrorLog(), an
//     http.Server whose ErrorLog the lint cannot see, and a call such as
//     http.ListenAndServe that makes a server with no ErrorLog.
//   - metric-labels: a metric label key that is not on the allowlist, a label
//     value that does not go through redact.URL, and a label value that the
//     lint cannot check.
//   - directive: a //privacy: comment that is not valid, or that allows
//     nothing.
//
// # Exceptions
//
// A comment in the code allows the findings of one rule on the lines that it
// covers:
//
//	//privacy:allow <rule> <ID>: <reason>
//	//privacy:source client-address <ID>: <reason>
//
// The ID is PRIV-NN, SEC-NN, b/NNN, or CL NN. An allow comment on its own
// line covers the simple statement, declaration, or struct field that starts
// on the next line; for a compound statement (if, for, switch) it covers the
// first line only. An allow comment after code covers its own line. A source
// comment goes in a function's doc comment: a call of that function is then a
// read of the client address, and the reads inside the function are allowed.
//
// The lint fails a comment with no ID or no reason, and a comment that allows
// nothing. exceptions.txt lists each comment that the code needs.
// TestRepository fails when the list and the code are different, so a new
// exception always shows in the diff of that file. After you add, move, or
// remove a comment, run:
//
//	go test ./internal/privacylint -run TestRepository -update
//
// # Limits
//
// The lint finds accidents, not deliberate evasion. It matches calls, types,
// and string literals. It does not follow data from one variable to another.
// It does not find a connection that a function value, reflect, or a
// listening socket opens, or a client address that comes through an interface
// with no RemoteAddr method. Review still decides design questions.
package privacylint
