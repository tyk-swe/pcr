# Byte-level transforms where a codec round trip is not faithful

Capture rewrites and fragmentation go through protocol codecs whenever
decoding and re-encoding reproduces the input byte for byte. Where that can't
be guaranteed (malformed or unknown bytes, non-canonical encodings), they edit
bytes directly through one shared link/VLAN/IP header walker. Keeping wire
values and malformed bytes faithful matters more than using one mechanism.
New code that edits bytes directly must say which faithfulness gap it avoids.
