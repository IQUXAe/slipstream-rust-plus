# Usage

This page documents the CLI surface for the Rust client and server binaries.

## slipstream-client

Required flags:

- --domain <DOMAIN>
- --resolver <IP:PORT> (repeatable; at least one in normal public mode)
- --cert <PATH> unless you explicitly pass --insecure-no-pin for dev/test only

These can also be supplied via SIP003 environment variables; see docs/sip003.md.

Common flags:

- --tcp-listen-host <HOST> (default: ::)
- --tcp-listen-port <PORT> (default: 5201)
- --transport <public-recursive-qname|legacy-edns0-payload> (default: public-recursive-qname)
- --congestion-control <bbr|dcubic> (optional; overrides congestion control for all resolvers)
- --cert <PATH> (PEM-encoded server leaf certificate; required by default)
- --insecure-no-pin (dev/test only; disables mandatory certificate pinning)
- --dev-authoritative <IP:PORT> (repeatable; development-only direct authoritative path)
- --public-safe-response-bytes <BYTES> (default: 360)
- --public-fast-response-bytes <BYTES> (optional; only usable after resolver probe confirms it)
- --gso (experimental; not implemented in the Rust loop)
- --keep-alive-interval <SECONDS> (default: 400)

Example:

```
./target/release/slipstream-client \
  --tcp-listen-port 7000 \
  --resolver 1.1.1.1:53 \
  --resolver 8.8.8.8:53 \
  --domain example.com \
  --cert ./cert.pem
```

Notes:

- Resolver addresses may be IPv4 or bracketed IPv6; mixed families are supported.
- IPv6 resolvers must be bracketed, for example: [2001:db8::1]:53.
- IPv4 resolvers require an IPv6 dual-stack UDP socket; slipstream attempts to set IPV6_V6ONLY=0, but some OSes may still require sysctl changes.
- Certificate pinning is mandatory by default; use --cert or explicitly opt into --insecure-no-pin for local development only.
- The pinned certificate must match the server leaf exactly; CA bundles are not supported.
- Copy the server `cert.pem` to the client and pass it with `--cert`.
- Resolver order follows the CLI; the first resolver becomes path 0.
- Resolver addresses must be unique; duplicates are rejected.
- Public-recursive mode carries client payload in QNAME and expects server payload in TXT answers.
- Arbitrary public-resolver OPT records are tolerated, but EDNS0 OPT is not used as a payload carrier in the default path.
- Use short domains when possible; this increases effective QNAME payload bytes.
- `--public-safe-response-bytes` is the conservative default intended to keep DNS responses within classic 512-byte UDP limits.
- `--public-fast-response-bytes` should only be enabled when you also configure the server for larger public responses and your resolver probe confirms it.
- `--dev-authoritative` keeps the direct authoritative path available for controlled environments only.
- When --congestion-control is omitted, authoritative paths default to bbr and recursive paths default to dcubic.
- Authoritative polling derives its QPS budget from picoquic’s pacing rate (scaled by the DNS payload size and RTT proxy) and falls back to cwnd if pacing is unavailable; `--debug-poll` logs the pacing rate, target QPS, and inflight polls.
- When QUIC has ready stream data queued, authoritative polling yields to data-bearing queries unless flow control blocks progress.
- Expect higher CPU usage and detectability risk; misusing it can overload resolvers/servers.

## slipstream-server

Required flags:

- --domain <DOMAIN> (repeatable)
- --cert <PATH>
- --key <PATH>

These can also be supplied via SIP003 environment variables; see docs/sip003.md.

Common flags:

- --dns-listen-host <HOST> (default: ::)
- --dns-listen-port <PORT> (default: 53)
- --target-address <HOST:PORT> (default: 127.0.0.1:5201)
- --public-safe-response-bytes <BYTES> (default: 360)
- --public-fast-response-bytes <BYTES> (optional; larger TXT responses for resolvers that passed probe)
- --max-connections <COUNT> (default: 256; caps concurrent QUIC connections)
- --fallback <HOST:PORT> (optional; forward non-DNS packets to this UDP endpoint)
- --idle-timeout-seconds <SECONDS> (default: 1200; set to 0 to disable)
- --reset-seed <PATH> (optional; 32 hex chars / 16 bytes; auto-created if missing)
- When binding to ::, slipstream attempts to enable dual-stack (IPV6_V6ONLY=0); if your OS disallows it, IPv4 DNS clients require sysctl changes or binding to an IPv4 address.
- With --fallback enabled, peers that have recently sent DNS stay DNS-only; while active they switch to fallback only after 16 consecutive non-DNS packets to avoid diverting DNS on stray traffic. DNS-only classification expires after an idle timeout without DNS traffic.
- Fallback sessions are created per source address without a hard cap; untrusted or spoofed UDP traffic can consume file descriptors/CPU. Use network filtering or rate limiting when exposing fallback to the public Internet, or disable --fallback if this is a concern.

Example:

```
./target/release/slipstream-server \
  --dns-listen-port 8853 \
  --target-address 127.0.0.1:5201 \
  --domain example.com \
  --domain tunnel.example.com \
  --cert ./cert.pem \
  --key ./key.pem \
  --reset-seed ./reset-seed
```

For quick tests you can use the sample certs in `fixtures/certs/` (test-only).
If the configured cert/key paths are missing, the server auto-generates a
self-signed ECDSA P-256 certificate (1000-year validity). To generate your
own manually:

```
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=slipstream"
```

## Local testing

For a local smoke test, the Rust to Rust interop script spins up a UDP proxy and TCP echo:

```
./scripts/interop/run_rust_rust.sh
```

See docs/interop.md for full details and C interop variants.

When multiple --domain values are provided, the server matches the longest
suffix in incoming QNAMEs.

Public-safe mode is the default. Public-fast mode should only be enabled when
the client probe confirms larger TXT responses through the selected public
resolvers.

## SIP003 plugin mode

See docs/sip003.md for SIP003 environment variable support and option syntax.
