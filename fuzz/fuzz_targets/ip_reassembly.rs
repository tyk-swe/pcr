#![no_main]

use libfuzzer_sys::fuzz_target;

mod ip_reassembly_support;

fuzz_target!(|data: &[u8]| {
    let _ = ip_reassembly_support::run(data);
});
