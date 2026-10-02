// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::{Block, Decoder, ENTRY_STRUCT_BYTES, Limits, integer};
use crate::protocol::application::http2::{Error, Limit};

fn limits() -> Limits {
    Limits {
        max_block_bytes: 1 << 20,
        max_header_bytes: 1 << 20,
        max_headers: 4096,
        max_table_bytes: 1 << 20,
    }
}

fn decoder_at(maximum: u32) -> Decoder {
    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.effective_max = maximum;
    decoder.ceiling = maximum;
    decoder
}

fn hex(text: &str) -> Bytes {
    let text: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let text = String::from_utf8(text).unwrap();
    Bytes::from(
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<u8>>(),
    )
}

fn pairs(block: &Block) -> Vec<(&[u8], &[u8])> {
    block
        .fields
        .iter()
        .map(|field| (field.name.as_ref(), field.value.as_ref()))
        .collect()
}

#[test]
fn rfc7541_c2_header_field_representations() {
    let mut decoder = Decoder::new(limits()).unwrap();
    let block = decoder
        .decode(
            &hex("400a637573746f6d2d6b65790d637573746f6d2d686561646572"),
            1,
        )
        .unwrap();
    assert_eq!(
        pairs(&block),
        [(b"custom-key".as_slice(), b"custom-header".as_slice())]
    );
    assert_eq!(block.decoded_bytes, 10 + 13 + 32);
    assert_eq!(decoder.buffered_bytes(), 10 + 13 + 32 + ENTRY_STRUCT_BYTES);
    assert_eq!(decoder.retained_origins(), [1]);

    let mut decoder = Decoder::new(limits()).unwrap();
    let block = decoder
        .decode(&hex("040c2f73616d706c652f70617468"), 2)
        .unwrap();
    assert_eq!(
        pairs(&block),
        [(b":path".as_slice(), b"/sample/path".as_slice())]
    );
    assert!(!block.fields[0].never_indexed);
    assert_eq!(decoder.buffered_bytes(), 0);

    let mut decoder = Decoder::new(limits()).unwrap();
    let block = decoder
        .decode(&hex("100870617373776f726406736563726574"), 3)
        .unwrap();
    assert_eq!(
        pairs(&block),
        [(b"password".as_slice(), b"secret".as_slice())]
    );
    assert!(block.fields[0].never_indexed);
    assert_eq!(block.fields[0].origins, [3]);
    assert_eq!(decoder.buffered_bytes(), 0);

    let mut decoder = Decoder::new(limits()).unwrap();
    let block = decoder.decode(&hex("82"), 4).unwrap();
    assert_eq!(pairs(&block), [(b":method".as_slice(), b"GET".as_slice())]);
}

const REQUEST_HEADERS: [[(&[u8], &[u8]); 5]; 3] = [
    [
        (b":method", b"GET"),
        (b":scheme", b"http"),
        (b":path", b"/"),
        (b":authority", b"www.example.com"),
        (b"", b""),
    ],
    [
        (b":method", b"GET"),
        (b":scheme", b"http"),
        (b":path", b"/"),
        (b":authority", b"www.example.com"),
        (b"cache-control", b"no-cache"),
    ],
    [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":path", b"/index.html"),
        (b":authority", b"www.example.com"),
        (b"custom-key", b"custom-value"),
    ],
];

fn request_list(which: usize) -> Vec<(&'static [u8], &'static [u8])> {
    REQUEST_HEADERS[which][..if which == 0 { 4 } else { 5 }].to_vec()
}

#[test]
fn rfc7541_c3_requests_without_huffman() {
    let mut decoder = Decoder::new(limits()).unwrap();
    let block = decoder
        .decode(&hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"), 1)
        .unwrap();
    assert_eq!(pairs(&block), request_list(0));
    assert_eq!(block.decoded_bytes, 42 + 43 + 38 + 57);
    assert_eq!(decoder.buffered_bytes(), 57 + ENTRY_STRUCT_BYTES);
    assert_eq!(decoder.retained_origins(), [1]);

    let block = decoder
        .decode(&hex("8286 84be 5808 6e6f 2d63 6163 6865"), 2)
        .unwrap();
    assert_eq!(pairs(&block), request_list(1));
    assert_eq!(block.fields[3].origins, [1, 2]);
    assert_eq!(decoder.buffered_bytes(), 110 + 2 * ENTRY_STRUCT_BYTES);
    assert_eq!(decoder.retained_origins(), [1, 2]);

    let block = decoder
        .decode(
            &hex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"),
            3,
        )
        .unwrap();
    assert_eq!(pairs(&block), request_list(2));
    assert_eq!(block.fields[3].origins, [1, 3]);
    assert_eq!(block.fields[4].origins, [3]);
    assert_eq!(decoder.buffered_bytes(), 164 + 3 * ENTRY_STRUCT_BYTES);
    assert_eq!(decoder.retained_origins(), [1, 2, 3]);
}

#[test]
fn rfc7541_c4_requests_with_huffman() {
    let mut decoder = Decoder::new(limits()).unwrap();
    let block = decoder
        .decode(&hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"), 1)
        .unwrap();
    assert_eq!(pairs(&block), request_list(0));
    assert_eq!(decoder.buffered_bytes(), 57 + ENTRY_STRUCT_BYTES);

    let block = decoder
        .decode(&hex("8286 84be 5886 a8eb 1064 9cbf"), 2)
        .unwrap();
    assert_eq!(pairs(&block), request_list(1));

    let block = decoder
        .decode(
            &hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"),
            3,
        )
        .unwrap();
    assert_eq!(pairs(&block), request_list(2));
    assert_eq!(decoder.buffered_bytes(), 164 + 3 * ENTRY_STRUCT_BYTES);
}

const RESPONSE_HEADERS: [[(&[u8], &[u8]); 6]; 3] = [
    [
        (b":status", b"302"),
        (b"cache-control", b"private"),
        (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"),
        (b"location", b"https://www.example.com"),
        (b"", b""),
        (b"", b""),
    ],
    [
        (b":status", b"307"),
        (b"cache-control", b"private"),
        (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"),
        (b"location", b"https://www.example.com"),
        (b"", b""),
        (b"", b""),
    ],
    [
        (b":status", b"200"),
        (b"cache-control", b"private"),
        (b"date", b"Mon, 21 Oct 2013 20:13:22 GMT"),
        (b"location", b"https://www.example.com"),
        (b"content-encoding", b"gzip"),
        (
            b"set-cookie",
            b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        ),
    ],
];

#[test]
fn rfc7541_c5_responses_without_huffman() {
    let mut decoder = decoder_at(256);
    let block = decoder
        .decode(
            &hex(
                "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 \
                 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 \
                 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
            ),
            1,
        )
        .unwrap();
    assert_eq!(pairs(&block), RESPONSE_HEADERS[0][..4].to_vec());
    assert_eq!(decoder.table_bytes, 222);
    assert_eq!(decoder.buffered_bytes(), 222 + 4 * ENTRY_STRUCT_BYTES);

    let block = decoder.decode(&hex("4803 3330 37c1 c0bf"), 2).unwrap();
    assert_eq!(pairs(&block), RESPONSE_HEADERS[1][..4].to_vec());
    assert_eq!(decoder.table_bytes, 222);
    assert_eq!(decoder.buffered_bytes(), 222 + 4 * ENTRY_STRUCT_BYTES);

    let block = decoder
        .decode(
            &hex(
                "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 \
                 3a32 3220 474d 54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 \
                 514b 425a 584f 5157 454f 5049 5541 5851 5745 4f49 553b 206d 6178 \
                 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e 3d31",
            ),
            3,
        )
        .unwrap();
    assert_eq!(pairs(&block), RESPONSE_HEADERS[2][..6].to_vec());
    assert_eq!(decoder.table_bytes, 215);
    assert_eq!(decoder.buffered_bytes(), 215 + 3 * ENTRY_STRUCT_BYTES);
}

#[test]
fn rfc7541_c6_responses_with_huffman() {
    let mut decoder = decoder_at(256);
    let block = decoder
        .decode(
            &hex(
                "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 \
                 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae \
                 43d3",
            ),
            1,
        )
        .unwrap();
    assert_eq!(pairs(&block), RESPONSE_HEADERS[0][..4].to_vec());
    assert_eq!(decoder.table_bytes, 222);

    let block = decoder.decode(&hex("4883 640e ffc1 c0bf"), 2).unwrap();
    assert_eq!(pairs(&block), RESPONSE_HEADERS[1][..4].to_vec());
    assert_eq!(decoder.table_bytes, 222);

    let block = decoder
        .decode(
            &hex(
                "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff \
                 c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af \
                 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 \
                 07",
            ),
            3,
        )
        .unwrap();
    assert_eq!(pairs(&block), RESPONSE_HEADERS[2][..6].to_vec());
    assert_eq!(decoder.table_bytes, 215);
}

#[test]
fn rfc7541_c1_prefixed_integers() {
    let mut pos = 0;
    assert_eq!(integer(&hex("0a"), &mut pos, 5).unwrap(), 10);
    assert_eq!(pos, 1);
    let mut pos = 0;
    assert_eq!(integer(&hex("1f9a 0a"), &mut pos, 5).unwrap(), 1337);
    assert_eq!(pos, 3);
    let mut pos = 0;
    assert_eq!(integer(&hex("2a"), &mut pos, 8).unwrap(), 42);
}

#[test]
fn integer_rejects_truncation_and_overflow() {
    let mut pos = 0;
    assert!(matches!(
        integer(&hex("ff"), &mut pos, 7),
        Err(Error::Compression(_))
    ));
    let mut pos = 0;
    assert!(matches!(
        integer(&hex("ffff ffff ffff ffff ffff ff"), &mut pos, 7),
        Err(Error::Compression(_))
    ));
    let mut pos = 0;
    assert!(matches!(
        integer(&hex("1f80 8080 8080 8080 8080 02"), &mut pos, 5),
        Err(Error::Compression(_))
    ));
    let mut pos = 0;
    assert_eq!(
        integer(&hex("1fe0 ffff ffff ffff ffff 01"), &mut pos, 5).unwrap(),
        u64::MAX
    );
    let mut pos = 0;
    assert!(matches!(
        integer(&hex("1fe0 ffff ffff ffff ffff 02"), &mut pos, 5),
        Err(Error::Compression(_))
    ));
}

#[test]
fn size_updates_track_acknowledged_maxima() {
    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.acknowledge_table_size(256).unwrap();
    let block = decoder.decode(&hex("3fe1 0182"), 1).unwrap();
    assert_eq!(pairs(&block), [(b":method".as_slice(), b"GET".as_slice())]);

    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.acknowledge_table_size(256).unwrap();
    assert!(matches!(
        decoder.decode(&hex("82"), 1),
        Err(Error::Compression(_))
    ));
}

#[test]
fn size_updates_require_smallest_then_final() {
    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.acknowledge_table_size(300).unwrap();
    decoder.acknowledge_table_size(64).unwrap();
    decoder.acknowledge_table_size(200).unwrap();
    let block = decoder.decode(&hex("3f21 3fa9 0182"), 1).unwrap();
    assert_eq!(pairs(&block), [(b":method".as_slice(), b"GET".as_slice())]);

    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.acknowledge_table_size(64).unwrap();
    let block = decoder.decode(&hex("2082"), 1).unwrap();
    assert_eq!(pairs(&block), [(b":method".as_slice(), b"GET".as_slice())]);

    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.acknowledge_table_size(64).unwrap();
    decoder.acknowledge_table_size(200).unwrap();
    let block = decoder.decode(&hex("203f a901 82"), 1).unwrap();
    assert_eq!(pairs(&block), [(b":method".as_slice(), b"GET".as_slice())]);

    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.acknowledge_table_size(64).unwrap();
    decoder.acknowledge_table_size(200).unwrap();
    assert!(matches!(
        decoder.decode(&hex("3fa9 0182"), 1),
        Err(Error::Compression(_))
    ));
}

#[test]
fn size_update_exceeding_ceiling_or_late_is_rejected() {
    let mut decoder = Decoder::new(limits()).unwrap();
    assert!(matches!(
        decoder.decode(&hex("3fe2 1f82"), 1),
        Err(Error::Compression(_))
    ));

    let mut decoder = Decoder::new(limits()).unwrap();
    assert!(matches!(
        decoder.decode(&hex("8220"), 1),
        Err(Error::Compression(_))
    ));
}

#[test]
fn eviction_removes_oldest_entries() {
    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.acknowledge_table_size(80).unwrap();
    let block = decoder
        .decode(&hex("3f31 4001 6101 6240 0163 0164 4001 6501 66"), 1)
        .unwrap();
    assert_eq!(
        pairs(&block),
        [
            (b"a".as_slice(), b"b".as_slice()),
            (b"c".as_slice(), b"d".as_slice()),
            (b"e".as_slice(), b"f".as_slice())
        ]
    );
    assert_eq!(decoder.table_bytes, 68);
    assert_eq!(decoder.buffered_bytes(), 68 + 2 * ENTRY_STRUCT_BYTES);
    let block = decoder.decode(&hex("bebf"), 2).unwrap();
    assert_eq!(
        pairs(&block),
        [
            (b"e".as_slice(), b"f".as_slice()),
            (b"c".as_slice(), b"d".as_slice())
        ]
    );
    assert!(matches!(
        decoder.decode(&hex("c0"), 3),
        Err(Error::Compression(_))
    ));
}

#[test]
fn oversized_entry_empties_table_without_error() {
    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.decode(&hex("4001 6101 62"), 1).unwrap();
    assert_eq!(decoder.buffered_bytes(), 34 + ENTRY_STRUCT_BYTES);
    let block = decoder.decode(&hex("2040 0163 0164"), 2).unwrap();
    assert_eq!(pairs(&block), [(b"c".as_slice(), b"d".as_slice())]);
    assert_eq!(decoder.buffered_bytes(), 0);
    assert_eq!(decoder.retained_origins(), Vec::<u64>::new());
}

#[test]
fn dynamic_origins_survive_referent_eviction() {
    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.decode(&hex("4001 6101 62"), 1).unwrap();
    decoder.decode(&hex("7e01 63"), 2).unwrap();
    decoder.decode(&hex("7e01 64"), 3).unwrap();
    assert_eq!(
        decoder.buffered_bytes(),
        34 + 42 + 50 + 3 * ENTRY_STRUCT_BYTES
    );
    assert_eq!(decoder.retained_origins(), [1, 2, 3]);

    let block = decoder.decode(&hex("be"), 4).unwrap();
    assert_eq!(pairs(&block), [(b"a".as_slice(), b"d".as_slice())]);
    assert_eq!(block.fields[0].origins, [1, 2, 3, 4]);

    decoder.decode(&hex("20"), 5).unwrap();
    assert_eq!(decoder.retained_origins(), Vec::<u64>::new());
    assert_eq!(decoder.buffered_bytes(), 0);
}

#[test]
fn limits_reject_zero_configuration() {
    for field in 0..4 {
        let mut limits = limits();
        match field {
            0 => limits.max_block_bytes = 0,
            1 => limits.max_header_bytes = 0,
            2 => limits.max_headers = 0,
            _ => limits.max_table_bytes = 0,
        }
        assert!(matches!(Decoder::new(limits), Err(Error::Invalid(_))));
    }
}

#[test]
fn limits_are_enforced_at_exact_boundaries() {
    let block = hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d");

    let mut exact = limits();
    exact.max_block_bytes = block.len();
    assert!(Decoder::new(exact).unwrap().decode(&block, 1).is_ok());
    let mut over = limits();
    over.max_block_bytes = block.len() - 1;
    assert!(matches!(
        Decoder::new(over).unwrap().decode(&block, 1),
        Err(Error::Limit(Limit::BlockBytes))
    ));

    let mut exact = limits();
    exact.max_header_bytes = 180;
    assert!(Decoder::new(exact).unwrap().decode(&block, 1).is_ok());
    let mut over = limits();
    over.max_header_bytes = 179;
    assert!(matches!(
        Decoder::new(over).unwrap().decode(&block, 1),
        Err(Error::Limit(Limit::HeaderBytes))
    ));

    let mut exact = limits();
    exact.max_headers = 4;
    assert!(Decoder::new(exact).unwrap().decode(&block, 1).is_ok());
    let mut over = limits();
    over.max_headers = 3;
    assert!(matches!(
        Decoder::new(over).unwrap().decode(&block, 1),
        Err(Error::Limit(Limit::HeaderCount))
    ));

    let charge = 57 + ENTRY_STRUCT_BYTES;
    let mut exact = limits();
    exact.max_table_bytes = charge;
    let mut decoder = Decoder::new(exact).unwrap();
    assert!(decoder.decode(&block, 1).is_ok());
    assert_eq!(decoder.buffered_bytes(), charge);

    let mut over = limits();
    over.max_table_bytes = charge - 1;
    assert!(matches!(
        Decoder::new(over).unwrap().decode(&block, 1),
        Err(Error::Limit(Limit::TableBytes))
    ));
}

#[test]
fn budgets_are_checked_before_expansion_and_insertion() {
    let mut small = limits();
    small.max_headers = 1;
    let mut decoder = Decoder::new(small).unwrap();
    assert!(matches!(
        decoder.decode(&hex("8240 7f"), 1),
        Err(Error::Limit(Limit::HeaderCount))
    ));
    assert!(decoder.table.is_empty());

    let mut small = limits();
    small.max_headers = 1;
    let mut decoder = Decoder::new(small).unwrap();
    assert!(matches!(
        decoder.decode(&hex("4001 6101 6240 7f"), 1),
        Err(Error::Limit(Limit::HeaderCount))
    ));
    assert_eq!(decoder.table.len(), 1);

    let mut tight = limits();
    tight.max_header_bytes = 76;
    assert!(
        Decoder::new(tight)
            .unwrap()
            .decode(&hex("8200 0161 0162"), 1)
            .is_ok()
    );
    let mut under = limits();
    under.max_header_bytes = 75;
    assert!(matches!(
        Decoder::new(under)
            .unwrap()
            .decode(&hex("8200 0161 0162"), 1),
        Err(Error::Limit(Limit::HeaderBytes))
    ));
    let mut under = limits();
    under.max_header_bytes = 42 + 31;
    assert!(matches!(
        Decoder::new(under)
            .unwrap()
            .decode(&hex("8200 0161 0162"), 1),
        Err(Error::Limit(Limit::HeaderBytes))
    ));

    let mut tight = limits();
    tight.max_header_bytes = 75;
    let mut decoder = Decoder::new(tight).unwrap();
    decoder.decode(&hex("4001 6101 62"), 1).unwrap();
    assert!(matches!(
        decoder.decode(&hex("82be"), 2),
        Err(Error::Limit(Limit::HeaderBytes))
    ));
}

#[test]
fn malformed_blocks_are_compression_errors() {
    for bytes in [
        "80",
        "ff7f",
        "ff",
        "40ff",
        "0084ff ff ff ff",
        "0081ff00",
        "00810000",
        "8220",
    ] {
        let mut decoder = Decoder::new(limits()).unwrap();
        assert!(
            matches!(decoder.decode(&hex(bytes), 1), Err(Error::Compression(_))),
            "{bytes}"
        );
    }
}

#[test]
fn huffman_accepts_short_eos_prefix_padding() {
    let mut decoder = Decoder::new(limits()).unwrap();
    let block = decoder.decode(&hex("0081 0700"), 1).unwrap();
    assert_eq!(pairs(&block), [(b"0".as_slice(), b"".as_slice())]);
}

#[test]
fn failures_poison_the_compression_context() {
    let mut decoder = Decoder::new(limits()).unwrap();
    decoder.decode(&hex("4001 6101 62"), 1).unwrap();
    assert!(matches!(
        decoder.decode(&hex("80"), 2),
        Err(Error::Compression(_))
    ));
    assert!(matches!(
        decoder.decode(&hex("82"), 3),
        Err(Error::Compression(_))
    ));
    assert!(matches!(
        decoder.decode(&Bytes::from_static(b""), 4),
        Err(Error::Compression(_))
    ));
    assert!(decoder.acknowledge_table_size(128).is_err());
}

#[test]
fn oversized_blocks_poison_the_decoder() {
    let mut limits = limits();
    limits.max_block_bytes = 4;
    let mut decoder = Decoder::new(limits).unwrap();
    assert!(matches!(
        decoder.decode(&hex("8286 8441 0f"), 1),
        Err(Error::Limit(Limit::BlockBytes))
    ));
    assert!(matches!(
        decoder.decode(&hex("82"), 2),
        Err(Error::Compression(_))
    ));
}
