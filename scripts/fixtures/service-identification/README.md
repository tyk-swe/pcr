# Original loopback TLS fixture

The fixed self-signed certificate and deliberately public key are original
AGPL-3.0-only test data, never production identity/trust anchors. The runner binds
IPv4/IPv6 loopback; retained DER proves byte fidelity, not authentication.
Python ssl serves fixtures, removing runtime OpenSSL installation requirements
on Linux/macOS/Windows; the evaluated client supplies its own TLS implementation.

Generated once on 2026-10-11:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 36500 \
  -keyout loopback-key.pem -out loopback-cert.pem \
  -subj '/CN=fixture.example.test/O=PacketcraftR original loopback fixture' \
  -addext 'subjectAltName=DNS:fixture.example.test,IP:127.0.0.1,IP:::1'
```

Do not regenerate during acceptance: expected certificate bytes are fixed.
