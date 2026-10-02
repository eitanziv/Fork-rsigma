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

#[test]
fn duplicate_matches_are_a_failure() {
    let case = engines::load_cases()
        .into_iter()
        .find(|case| case.name == "and_fields")
        .unwrap();
    let results = vec![(case, Ok(Outcome::Matched(vec![0, 0])))];
    let failures = engines::check_outcomes("lynxdb", &results);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("matched [0, 0], expected [0]"))
    );
}

#[test]
fn known_failure_must_have_the_recorded_outcome() {
    let case = engines::load_cases()
        .into_iter()
        .find(|case| case.name == "regex_anchored")
        .unwrap();

    let recorded = vec![(case.clone(), Ok(Outcome::Matched(Vec::new())))];
    assert!(engines::check_outcomes("lynxdb", &recorded).is_empty());

    let changed = vec![(case, Err("container crashed".to_string()))];
    let failures = engines::check_outcomes("lynxdb", &changed);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("known failure changed"))
    );
}
