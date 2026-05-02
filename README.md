# Slipstream Rust Plus

Slipstream Rust Plus tunnels QUIC over DNS with a public-recursive-first design.
The default mode is built for reachability through public DNS resolvers and
prioritizes compatibility and anti-blocking behavior over peak throughput.

## Default transport

- Default client transport: `public-recursive-qname`
- Client -> server payload: QNAME only
- Server -> client payload: TXT answer only
- EDNS0 OPT: used only as a normal DNS UDP size advertisement, not as a tunnel payload carrier
- Certificate pinning: required by default

This makes the main path suitable for public recursive resolvers such as
`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, and other public resolvers where TXT answers
are preserved.

## Build

```bash
git clone https://github.com/Fox-Fig/slipstream-rust-plus.git
cd slipstream-rust-plus
git submodule update --init --recursive
cargo build -p slipstream-client -p slipstream-server --release
```

## Run

Start the server:

```bash
./target/release/slipstream-server \
  --domain example.com \
  --target-address 127.0.0.1:5201 \
  --cert ./cert.pem \
  --key ./key.pem \
  --reset-seed ./reset-seed
```

Copy the server leaf certificate to the client machine and pin it:

```bash
scp user@server:/path/to/cert.pem ./cert.pem
```

Start the client:

```bash
./target/release/slipstream-client \
  --domain example.com \
  --resolver 1.1.1.1 \
  --resolver 8.8.8.8 \
  --resolver 9.9.9.9 \
  --cert ./cert.pem \
  --tcp-listen-port 5201
```

## Public DNS notes

- Shorter domains improve QNAME capacity and throughput.
- More resolvers are not always better; prefer a small set of healthy resolvers.
- `--public-safe-response-bytes` keeps responses small enough for classic 512-byte DNS paths.
- `--public-fast-response-bytes` is optional and should only be used when the resolver probe confirms larger TXT responses work for your chosen resolvers.
- `--dev-authoritative` is a development-only escape hatch for direct authoritative paths and is not the default.
- `--insecure-no-pin` exists for local dev/test only and disables mandatory certificate pinning.

## Docs

- Usage: [docs/usage.md](docs/usage.md)
- DNS codec: [docs/dns-codec.md](docs/dns-codec.md)
- Protocol notes: [docs/protocol.md](docs/protocol.md)
- Configuration: [docs/config.md](docs/config.md)
