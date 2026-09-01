# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.0

Initial code.

The GDPR personal-data-access audit sink as first released: the synchronous service other
services call to record who accessed whose personal data, when, and on what lawful basis.
Producers post one access-record envelope per data touch; the service seals it into an
append-only, subject-indexed store that can answer accountability queries, data-subject
access requests, and tamper-evidence checks. MIT.
