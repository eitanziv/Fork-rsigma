#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises the Lucene reverse frontend end to end: the untrusted query string
// drives the tokenizer, the boolean parser, leaf parsing, HIR assembly, the
// raise back to a Sigma rule, and YAML emission. Every stage must fail
// gracefully (a structured error) rather than panic on malformed input.
fuzz_target!(|data: &[u8]| {
    let Ok(query) = std::str::from_utf8(data) else {
        return;
    };
    let ctx = rsigma_convert::ReverseCtx {
        product: Some("test".into()),
        ..Default::default()
    };
    let queries = [query.to_string()];
    let _ = rsigma_convert::reverse_collection(&rsigma_convert::LuceneFrontend, &queries, &ctx);
});
