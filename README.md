# eidas-validate

Open-source validation of qualified eIDAS timestamps against the EU Trusted Lists.

Submit an RFC 3161 timestamp token and this service tells you two separate
things: whether the token is structurally sound, and what the authority that
issued it actually is. It does not combine them into a single verdict, because
they answer different questions and only one of them is hard to forge.

## Why it exists

Verification should not require trusting the party who issued the thing being
verified. Publishing the validator makes that argument concrete rather than
rhetorical. Anyone can run this, read it, or check its answers against the
public lists themselves.

It validates timestamps from any EU trust service provider, not one supplier.
The trusted list system makes that barely more work than validating one, and a
tool that only validates its author's supplier is a utility rather than
infrastructure.

## What it does

- Verifies the timestamp token's signature against its embedded certificate
- Confirms the message imprint against the document or digest, where supplied
- Establishes the issuing authority independently, through the EU List of
  Trusted Lists and the member state trusted lists
- Determines qualified status **as at the moment of stamping**, not as at now
- Reports the evidence behind that finding: which list, which sequence number,
  which service entry, what status, from when
- States the freshness of the trusted list data behind the answer

## What it deliberately does not do

**It does not merge signature validity with trust anchoring.** A token forged by
an attacker running their own timestamp authority passes both the signature
check and the message imprint check. Only the trust anchor catches it. Any
interface built on this output must keep the two apart.

**It does not treat a check it could not perform as a check that passed.** Every
result is one of valid, invalid, or indeterminate. An unreachable trusted list
produces indeterminate, never valid.

**It does not judge historic tokens by today's status.** A qualified timestamp
is qualified as at the moment it was issued. If a service is later withdrawn,
tokens it issued while granted remain qualified, and the trusted lists carry
status history so this can be established. Equally, a token stamped before a
service was granted was never qualified, whatever the list says today.

**It does not retain what you submit.** No request body is stored or logged.

**It does not editorialise about withdrawal.** Withdrawal for cause and an
orderly wind-down are substantively different, and the trusted lists do not
reliably distinguish them in machine-readable form. The status and the dates
are reported as fact. The inference is left to the reader.

## Qualified and recognised are not grades of the same thing

Tokens from FreeTSA and from the common commercial authorities are recognised
by pinned fingerprint and reported as valid but **not qualified**. They carry no
eIDAS Article 41 presumption. This is a difference in kind, not in degree, and
the output does not blur it.

## Why Java, and why DSS

This wraps [DSS](https://github.com/esig/dss), the digital signature library
built and maintained by the European Commission's DIGITAL programme, which is
the reference implementation of the relevant ETSI standards.

Under challenge, the answer is that validation used the Commission's own
library. A hand-written implementation would ask a court to prefer one reading
of a standard over the standard's own reference implementation.

DSS also solves three problems that are individually difficult: verifying the
trusted list's own XML signature, establishing each list's authenticity through
the Commission's List of Trusted Lists, and determining status at a point in
the past rather than now.

## Availability

Hosted on Render's free tier, which suspends the service after fifteen minutes
without a request. A request arriving while it is suspended can take up to
about two minutes to return, while the instance restarts. This is a hosting
characteristic, not a fault in the validation itself, and it will be removed
once there is enough traffic to justify a paid instance.

## Structure

| Module | Contents |
| --- | --- |
| `core` | Validation logic and vocabulary. No HTTP layer, no framework. |
| `api` | HTTP service. Public, unauthenticated, rate limited, retains nothing. |

## Building

Requires JDK 21 and Maven.

```
mvn clean test
```

## Status

Early. The vocabulary and interfaces are settled; the DSS wiring is in progress.
Not yet suitable for reliance.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

Published by [Provlyn Ltd](https://www.provlyn.com), company number 17185877,
registered in England and Wales.
