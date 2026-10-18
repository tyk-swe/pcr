# Audit TLS fixtures

The RSA private key is deliberately public test data, never a production key.
The two leaf certificates were generated for PacketcraftR's loopback audit tests
and signed by the existing original fixture root in
`scripts/fixtures/service-identification/loopback-cert.pem`. They have DNS
`audit.example.test` and IP `127.0.0.1` subject alternative names and server-auth
usage. The valid leaf spans 2020–2120; the expired leaf spans 2020–2021.
All files are original AGPL-3.0-only test material.
