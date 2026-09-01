# Security policy

This service is the **record of who looked at whose personal data**. Other services call it every
time they touch personal data; it seals each record and keeps it queryable by data subject, so an
organisation can answer for its own access — accountability under Regulation 2016/679 Art. 5(2),
and a subject access request under Art. 15.

Two things follow, and they pull in opposite directions. The log has to be **provably
un-tampered**, because a record that can be quietly changed proves nothing. And the log is
**itself personal data**, minimised and time-bounded on purpose, because a complete history of who
read what is exactly the material an attacker would want.

So its worst failure is one of two: **a stored record altered, added or removed without the seals
saying so**, or **the log becoming the leak it exists to police** — an identifying value landing in
a store whose contract is pseudonymous references only.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/go-make-bytes/access-audit/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- the configuration it needs, if it only appears under particular settings;
- whether you have told anyone else, and whether a disclosure date already binds you.

**Please do not send us real access records, seal keys, service tokens or national identifiers.**
A redacted example, or the shape of the value, explains almost any finding here — and a real record
is someone's personal data twice over.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

**Anything that lets a stored record change without the evidence saying so.**

- A record that can be altered or deleted outside the purge path — the store is append-only by
  construction, so a route to `UPDATE`, or a `DELETE` reachable other than through purge, defeats
  the whole point of the log.
- A seal that verifies over something other than the producer's own content, or that keeps
  verifying after the content changes. The canonical form is a fixed projection of the envelope; a
  change that makes two different records seal to the same value, or that lets a stored record be
  re-serialised into a different one that still matches, is a serious finding.
- A period checkpoint being overwritten, recomputed from already-altered rows, or written for a
  period that is not closed. Checkpoints are write-once precisely so that a retained period can be
  proven intact.
- A seal or checkpoint comparison that is not constant-time, or that treats a verification error as
  a pass.
- A purge that removes records **inside** the accountability window, or that skips the legal-hold
  check. A hold exists for an active investigation or dispute; deleting through one destroys
  evidence someone is relying on.

**The seal key.**

- The key reaching the database, a log line, an error body, a response, a metric label or a crash
  dump. It lives in memory only, and that is the single reason table-only access cannot forge a
  seal.
- Starting up with a missing, short or otherwise invalid key. Start-up is fail-closed on purpose; a
  configuration hole that boots anyway is how a store full of unverifiable seals is created quietly.

**The pseudonymity contract — this store must not become the identifying one.**

- A value that identifies a person directly — a national identifier, an e-mail address, a personal
  name — reaching `data_subjects`, and with it the subject index. The sink rejects those shapes
  defensively; a way past that check is a finding even though the producer is also contractually
  wrong to have sent it.
- Content surviving into a stored record: document bytes, free text, or an attribute value that
  should have been stripped or truncated. This log records *that* an access happened, never what
  was in the data.
- A DSAR read, an error message or a security event that discloses more than the caller's own
  system — including a subject's existence in another deployment's records.

**Authorisation and caller isolation.**

- Reaching any `/v1` route without a valid, DPoP-bound service token, with a token bound to a
  different key, or with a scope the route does not require. The admin routes — verify, legal
  holds, purge — are the ones with real consequences.
- `source_service` or `system` being taken from the request body rather than from the authenticated
  identity. A producer that can name itself can also frame another service.
- An idempotency key that lets a retry become a second stored record, or lets one caller's record
  displace another's.

Denial of service and findings that need an already-compromised host or an already-authenticated
administrator are in scope but lower priority. Reports about outdated dependencies are welcome
where you can show the vulnerable path is actually reachable.

## What is deliberately not a finding

This service **records; it does not judge**. It does not decide whether an access was lawful, does
not evaluate the legal basis a producer asserts, and does not authenticate the data subject behind
a request — the caller holding the read scope is trusted to have done that. A report that a stored
record was wrong is a finding against whoever produced it, not against this service, unless this
service mishandled what it was given. A report that an API *implies* it validated any of that, or
that an integrator is likely to read it that way, **is** a real finding.

Two documented limitations are not vulnerabilities in themselves, though a concrete exploitation of
either is: seal-key rotation is not implemented, so one key protects the whole retained store; and
the in-memory backend is non-durable and selected only when no database is configured.

## Scope

This policy covers the code in this repository. It does not cover the client library that producers
use to deliver records, the database schema and its procedures as deployed by an operator, or any
deployment operated by someone other than us — report those to the parties that run them. How a
deployment configures this service is the operator's responsibility, but a report that a **default**
is unsafe is very much in scope.

## Supported versions

Security fixes land on the most recent release. Older tags are not patched; if you are pinned to
one, the fix is to move forward.
