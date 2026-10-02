//! Keeps the engine case expectations honest: rsigma's evaluator must agree
//! with every case's `matches`, so the engine tests compare backends against
//! the same answer the engine gives. Needs no Docker, so it runs in the
//! workspace test job.

mod engines;

use engines::Outcome;

#[test]
fn eval_agrees_with_case_expectations() {
    let results: Vec<_> = engines::load_cases()
        .into_iter()
        .map(|case| {
            let got = engines::eval_matches(&case);
            (case, Ok(Outcome::Matched(got)))
        })
        .collect();
    engines::assert_outcomes("eval", &results);
}
