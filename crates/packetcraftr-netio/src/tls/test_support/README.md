# TLS transport fixtures

Original isolated AGPL-3.0-only data, not production keys/trust anchors. Self-signed
ECDSA P-256 `fixture.example.test` DER and unencrypted PKCS#8 key support TLS 1.2/1.3
contracts. Separately generated `wrong-key.der` proves certificate observation never
bypasses peer handshake-signature verification. No chain/hostname trust is asserted.

Generated locally with OpenSSL in October 2026: `req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes`,
`x509 -outform DER`, and `pkcs8 -topk8 -nocrypt -outform DER`.
Tests need neither OpenSSL nor a network connection. Keep bytes fixed.
