#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr::workflow::dns::{Limits, QueryType, decode_response, decode_tcp_frame};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, wire)) = data.split_first() else {
        return;
    };
    let wire = &wire[..wire.len().min(u16::MAX as usize + 2)];
    let transaction_id = wire
        .get(..2)
        .map(|id| u16::from_be_bytes([id[0], id[1]]))
        .unwrap_or(0);
    let query_type = match mode % 6 {
        0 => QueryType::A,
        1 => QueryType::Aaaa,
        2 => QueryType::Cname,
        3 => QueryType::Mx,
        4 => QueryType::Txt,
        _ => QueryType::Any,
    };
    let limits = Limits {
        max_message_bytes: u16::MAX as usize,
        max_records: 64,
        max_name_pointers: 32,
        max_txt_strings: 64,
        max_txt_bytes: 4096,
        max_rejected_records: 32,
        ..Limits::default()
    };
    if mode & 0x80 == 0 {
        let _ = decode_response(wire, "example.test", query_type, transaction_id, limits);
    } else {
        let _ = decode_tcp_frame(wire, "example.test", query_type, transaction_id, limits);
    }
});
