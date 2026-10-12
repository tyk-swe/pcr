# TLS transport fixtures

These original, isolated fixtures are not trust anchors or production keys.
The self-signed ECDSA P-256 certificate names `fixture.example.test`; its DER
certificate and unencrypted PKCS#8 key support deterministic TLS 1.2 and TLS 1.3
transport contracts. `wrong-key.der` is a separately generated P-256 private
key used to prove that observing a certificate does not bypass verification of
the peer's handshake signature. No certificate trust or hostname authentication
claim is made by these tests.

The files were generated locally with OpenSSL in October 2026, using
`req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes`,
`x509 -outform DER`, and `pkcs8 -topk8 -nocrypt -outform DER`. Tests require
neither OpenSSL nor a network connection. The fixture source and keys carry the
repository's AGPL-3.0-only license.
