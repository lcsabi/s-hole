<!--
  Thanks for sending a PR! Please keep this template — it doubles as a
  reviewer checklist and as the body of the eventual merge commit.
-->

## Summary

<!-- 1–3 bullets describing the change. -->

## Linked CL / Bug

<!-- e.g. CL 19, b/030, R-23, or — for trivial / docs-only changes. -->

## Why

<!-- Optional. The "why" is often more useful in review than the "what". -->

## Test plan

- [ ] `make check` passes locally (fmt, vet, lint, tests)
- [ ] `go test -race -count=1 ./...` clean
- [ ] Manual verification (steps below or "n/a"):

  <!-- e.g. ran the binary on Linux and verified `kill -HUP $pid` triggers a refresh -->

## Risk

<!-- What's the worst that could happen if this merges and the change is wrong?
     If "nothing — pure docs / tests", say so. Otherwise note any user-visible
     impact and the rollback story. -->
