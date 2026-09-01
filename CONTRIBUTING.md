# Contributing

Thank you for considering a contribution. Bug reports, fixes and improvements are welcome. For
anything that could be exploited, use the private route in [SECURITY.md](SECURITY.md) — never a
public issue.

For anything larger than a small fix, please open an issue first and describe what you want to
change and why. This service is an evidence store: several of its properties are load-bearing for
people who will never read the code, so a change that fights its design is better redirected before
it is written than after.

## Building and testing

You need the Go toolchain at the version named in [go.mod](go.mod). Every dependency is public, so
nothing needs credentials, a `GOPRIVATE` setting or a vendor directory. The gate a change must pass
is the same one CI runs:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
```

Three more checks run in CI and are worth running before you push:

- **Lint** — `golangci-lint run`, at the version pinned in
  [.github/workflows/ci.yml](.github/workflows/ci.yml); the repo's [.golangci.yml](.golangci.yml)
  carries the configuration.
- **Vulnerabilities** — `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`.
- **The image** — CI builds it, generates an SBOM, fails on HIGH/CRITICAL findings from a
  vulnerability scan, and signs it. A change to the [Dockerfile](Dockerfile) should be built
  locally before you push, because that job is slow to fail.

The committed tree must already be tidy: CI runs `go mod tidy -diff` and fails if it would change
anything, so run `go mod tidy` after touching dependencies. All Go code is `gofmt`-formatted, and
`.gitattributes` pins Go files to LF line endings — leave that alone, it keeps the tidy-diff gate
stable across platforms.

Tests need no database, no network and no Docker: the in-memory store backend and a header-driven
stub auth middleware (`TestApp` in [testing.go](testing.go)) stand in for both. If a change makes a
test need a live PostgreSQL, that is a design signal worth raising in the issue rather than solving
with a fixture.

## What a change to this service needs

Read the **Security invariants** and **Tamper evidence & retention** sections of the
[README](README.md) before changing anything on the append, seal or purge paths. They are not
documentation of good intentions; each one is the reason a specific class of defect cannot happen.

The three that carry the most weight:

- **The canonical form is a stored-data contract, not an implementation detail.** Every seal in
  every deployment was computed over the bytes today's canonicalisation produces. Change how a
  record is projected — field order, sorting, timestamp normalisation, which fields are included —
  and every already-stored seal stops verifying, which reads to an operator as tampering. Such a
  change is a migration with a re-seal plan, never a refactor, and it needs a test that pins the
  bytes.
- **Append-only, and purge is the only deletion.** The database role holds EXECUTE-only grants and
  reaches nothing but procedures; deletion exists solely inside the purge path, and that path skips
  subjects under legal hold. A change that opens any other route to modify or remove a stored
  record is the change, not a side effect of one.
- **The store is personal data, so it stays minimal.** `data_subjects` carries pseudonymous
  references only, and the sink rejects values that look like national identifiers, e-mail
  addresses or personal names; content-bearing attribute keys are stripped and values truncated.
  Loosening that check — including "just for this one producer" — turns an accountability log into
  a second copy of the data it polices.

Also load-bearing:

- **The seal key never becomes durable.** It is held in memory, loaded from the secret store, and
  must not reach the database, a log line, an error body or a response. Start-up fails closed on a
  missing or too-short key; keep it that way.
- **Checkpoints are write-once**, and only for closed periods. That is what lets a retained period
  be proven intact after older ones are purged.
- **Identity comes from the token.** `source_service` and `system` are derived from the
  authenticated caller and must never be readable from the request body.
- **Both store backends implement the same semantics.** The in-memory backend is what the tests
  prove behaviour against, so a rule that lands in only one of the two is a rule the tests cannot
  see. The PostgreSQL half of a rule may also live in the schema's procedures, which are deployed
  separately from this repository — a domain-rule change that stops at the Go layer is incomplete.
- **Appends are idempotent on `event_id`.** Producers retry from an outbox; a change that lets a
  retry create a second row corrupts every count, and with it the period checkpoints.

## Proposing a change

- Work on a branch and open a pull request against `develop`. `develop` is merged into `main` and
  tagged there when a release goes out, so `main` is never committed to directly.
- **Sign off every commit.** This project uses the
  [Developer Certificate of Origin](https://developercertificate.org/): by adding a
  `Signed-off-by: Your Name <you@example.org>` line you certify that you wrote the change or
  otherwise have the right to submit it under this project's licence. `git commit -s` adds the line
  for you; the name and address must match the commit author. A pull request whose commits lack it
  fails the DCO check and cannot be merged.
- Keep the change focused: one concern per pull request.
- A change in behaviour comes with a test that fails without it.
- Match the style around you — naming, error handling, comment density. Comments explain what and
  why in plain domain terms; a reference to a standard is cited in the bracket form already used in
  the code.
- A change an operator or an integrator can feel — a new or changed endpoint, field, error code,
  configuration knob or default — belongs in [CHANGELOG.md](CHANGELOG.md) in the same pull request.
- Pull requests also run a dependency review. A new dependency needs a reason the standard library
  or the existing ones cannot cover.

## Licence

This project is licensed under the **MIT licence** (see [LICENSE](LICENSE)). By submitting a
contribution you agree that it is provided under the same licence — you keep the copyright in what
you wrote, and everyone, including commercial users, may use it under MIT's terms.
