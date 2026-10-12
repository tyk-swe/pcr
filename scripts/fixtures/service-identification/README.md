# Original loopback TLS fixture

`loopback-cert.pem` and `loopback-key.pem` are a self-signed certificate and
its deliberately public test key, generated once for PacketcraftR's original
loopback fixtures. They have no production identity or trust purpose. The
acceptance runner binds only IPv4/IPv6 loopback and retains the presented DER
certificate as an unauthenticated observation.

The checked-in assets remove an OpenSSL installation requirement from runtime
acceptance on Linux, macOS, and Windows. Python's standard-library `ssl` serves
the fixture; the implementation under evaluation supplies its own TLS client.
The key and certificate are project-authored test data under AGPL-3.0-only.

Generation on 2026-10-11 used:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 36500 \
  -keyout loopback-key.pem -out loopback-cert.pem \
  -subj '/CN=fixture.example.test/O=PacketcraftR original loopback fixture' \
  -addext 'subjectAltName=DNS:fixture.example.test,IP:127.0.0.1,IP:::1'
```

Do not regenerate these assets during acceptance. Comparing retained certificate
bytes to the fixed fixture checks observation fidelity without asserting trust.
