use super::*;

const NATIVE: &str =
    "c\ttests/data/controls/c.patch\tnative\tnightly\tdcbor\tall\tlib\ta::b\t-\tfailed\tboom";
const FIXTURE: &str = "t\ttests/data/controls/t.patch\tnative\tstable\tdcbor-derive\t-\tui\tsuite\ttests/ui/fail/x.rs\tfailed\tExpected test case to fail to compile, but it succeeded.";
const MODEL: &str =
    "m\ttests/data/controls/m.patch\tloom\t-\t-\t-\t-\t-\t-\tfailed\tCausality violation";
const BUILT: &str =
    "w\ttests/data/controls/w.patch\tshuttle\t-\t-\t-\t-\t-\t-\tbuild_refused\tmore than a quantum";
const MIRI: &str = "u\ttests/data/controls/u.patch\ttree\tnightly\tdcbor\tcustom-std-collections\tlib\ta::b\t-\tundefined_behavior\tUndefined Behavior";

fn table(rows: &[&str]) -> String {
    let mut text = "# a comment\n\n".to_string();
    for row in rows {
        text.push_str(row);
        text.push('\n');
    }
    text
}

fn one(row: &str) -> Control {
    parse(&table(&[row])).expect("a valid table").remove(0)
}

#[test]
fn every_row_is_read_with_its_runner_and_outcome() {
    let controls = parse(&table(&[NATIVE, FIXTURE, MODEL, BUILT, MIRI])).expect("a valid table");
    assert_eq!(controls.len(), 5);
    assert_eq!(controls[0].runner, Runner::Native);
    assert_eq!(controls[0].expected, Outcome::Failed);
    assert_eq!(controls[1].fixture.as_deref(), Some("tests/ui/fail/x.rs"));
    assert_eq!(controls[2].runner, Runner::Model(Checker::Loom));
    assert_eq!(controls[3].runner, Runner::Model(Checker::Shuttle));
    assert_eq!(controls[3].expected, Outcome::BuildRefused);
    assert_eq!(controls[4].runner, Runner::Miri("tree"));
    assert_eq!(controls[4].expected, Outcome::UndefinedBehavior);
    for (control, row) in controls.iter().zip([NATIVE, FIXTURE, MODEL, BUILT, MIRI]) {
        assert_eq!(control.render(), row, "a row renders as written");
    }
    let mut runners = vec![
        Runner::Native,
        Runner::Model(Checker::Loom),
        Runner::Model(Checker::Shuttle),
    ];
    runners.extend(
        crate::miri::MIRI_MODELS
            .iter()
            .map(|model| Runner::Miri(model)),
    );
    for runner in runners {
        assert_eq!(Runner::parse(runner.name()), Some(runner));
        assert!(
            Runner::unknown("x").contains(runner.name()),
            "the refusal names {}",
            runner.name()
        );
    }
}

/// Planted: each malformed row is refused, naming its line.
#[test]
fn a_malformed_row_is_refused() {
    let cases = [
        (
            "c\ttests/data/controls/c.patch\tnative".to_string(),
            "columns",
        ),
        (
            NATIVE.replace("tests/data/controls/c.patch", "src/c.patch"),
            "no diff",
        ),
        (NATIVE.replace("c.patch", "c.diff"), "no diff"),
        (NATIVE.replace("\tnative\t", "\tmiri\t"), "no runner"),
        (
            NATIVE.replace("\tfailed\t", "\tpass\t"),
            "no refusal outcome",
        ),
        (
            NATIVE.replace("\tfailed\t", "\tcaught\t"),
            "no refusal outcome",
        ),
        (NATIVE.replace("\tboom", "\t-"), "no pattern"),
        (NATIVE.replace("\ta::b\t", "\t-\t"), "only those"),
        (NATIVE.replace("\tnightly\t", "\tbeta\t"), "only those"),
        (MODEL.replace("\tloom\t-", "\tloom\tnightly"), "only those"),
        (NATIVE.replace("\tdcbor\t", "\t\t"), "empty"),
        // Miri is a nightly component and runs no trybuild fixture.
        (MIRI.replace("\tnightly\t", "\tstable\t"), "only those"),
        (
            MIRI.replace("\ta::b\t-\t", "\ta::b\ttests/ui/fail/x.rs\t"),
            "only those",
        ),
        (MIRI.replace("\ta::b\t", "\t-\t"), "only those"),
    ];
    for (row, expected) in cases {
        let refused = parse(&table(&[&row])).expect_err(&row);
        assert!(refused.contains(expected), "{row}: {refused}");
        assert!(refused.contains(":3:"), "{row}: {refused}");
    }
    assert!(
        parse(&table(&[NATIVE, NATIVE]))
            .expect_err("twice")
            .contains("twice")
    );
    let renamed = MODEL.replace(
        "m\ttests/data/controls/m.patch",
        "c\ttests/data/controls/d.patch",
    );
    assert!(
        parse(&table(&[NATIVE, &renamed]))
            .expect_err("two diffs")
            .contains("names")
    );
    assert!(parse(&table(&[])).is_err(), "an empty table");
}

/// Planted: a diff on disk with no row, and a row whose diff is missing,
/// are each named.
#[test]
fn the_table_and_the_diffs_agree() {
    let root = std::env::temp_dir().join(format!("dcbor-controls-{}", std::process::id()));
    let directory = root.join(DIRECTORY);
    std::fs::create_dir_all(&directory).expect("a fixture directory");
    std::fs::write(directory.join("c.patch"), "").expect("a fixture diff");
    std::fs::write(directory.join("orphan.patch"), "").expect("a fixture diff");
    let controls = parse(&table(&[NATIVE, MODEL])).expect("a valid table");
    let faults = completeness(&root, &controls).expect("a readable directory");
    std::fs::remove_dir_all(&root).expect("the fixture removed");
    assert_eq!(faults.len(), 2, "{faults:#?}");
    assert!(faults[0].contains("orphan.patch") && faults[0].contains("no control runs"));
    assert!(faults[1].contains("m.patch") && faults[1].contains("does not exist"));
}

/// Planted: each hunk an exact application (`patch --fuzz=0`) cannot place
/// where its header says is named at its header's line: context shorter
/// after the change than before, as the ratchet control's hunk was, shorter
/// before than after away from the file's start, a header whose counts are
/// not its body's, a header that is no range; the shapes it does place pass,
/// a hunk at the file's first line leading with less among them.
#[test]
fn every_hunk_an_exact_application_cannot_place_is_refused() {
    let balanced = "--- a.rs\n+++ a.rs\n@@ -4,7 +4,7 @@\n a\n b\n c\n-d\n+e\n f\n g\n h\n";
    assert_eq!(hunk_faults("d", balanced), Vec::<String>::new());
    let at_start = "--- a.rs\n+++ a.rs\n@@ -1,4 +1,4 @@\n-a\n+b\n c\n d\n e\n";
    assert_eq!(hunk_faults("d", at_start), Vec::<String>::new());
    let cases = [
        (
            "--- a.rs\n+++ a.rs\n@@ -4121,4 +4121,3 @@\n a\n b\n-c\n d\n",
            "d:3: 2 lines of leading context and 1 of trailing",
        ),
        (
            "--- a.rs\n+++ a.rs\n@@ -9,4 +9,3 @@\n a\n-b\n c\n d\n",
            "d:3: 1 lines of leading context and 2 of trailing",
        ),
        (
            "--- a.rs\n+++ a.rs\n@@ -4,8 +4,8 @@\n a\n b\n c\n-d\n+e\n f\n g\n h\n",
            "d:3: the header counts 8 old and 8 new lines, the body holds 7 and 7",
        ),
        (
            "--- a.rs\n+++ a.rs\n@@ -x +y @@\n a\n",
            "d:3: a hunk header that is not",
        ),
        (
            "--- a.rs\n+++ a.rs\n@@ -4,3 +4,3 @@\n a\n-b\n+c\n d\n--- b.rs\n+++ b.rs\n@@ -7,2 +7,1 @@\n a\n-b\n",
            "d:10: 1 lines of leading context and 0 of trailing",
        ),
    ];
    for (diff, expected) in cases {
        let faults = hunk_faults("d", diff);
        assert!(
            faults.len() == 1 && faults[0].starts_with(expected),
            "{diff:?}: {faults:#?}"
        );
    }
}

/// A run of the one selected test, failing with its own diagnostic.
const REFUSED: &str = "running 1 test\ntest a::b ... thread 'a::b' panicked: boom\nFAILED\n\nfailures:\n    a::b\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out\n";
const RESTORED: &str = "running 1 test\ntest a::b ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out\n";

#[test]
fn a_control_is_refused_by_its_own_test_and_outcome() {
    let control = one(NATIVE);
    assert_eq!(judge(&control, Outcome::Failed, REFUSED), Ok(()));
    assert_eq!(restored(&control, Outcome::Pass, RESTORED), Ok(()));
}

/// Planted: a pass, another outcome than planned (a segfault naming the
/// pattern), an ignored test, a run of two tests whose other one printed the
/// pattern, a build failure, and a failure without the pattern are each no
/// refusal; a restored run that did not run alone and pass is no green.
#[test]
fn every_other_run_is_no_refusal() {
    let control = one(NATIVE);
    let passed = judge(&control, Outcome::Pass, RESTORED).expect_err("a pass");
    assert!(
        passed.contains("where the planted defect's refusal is failed"),
        "{passed}"
    );
    let crashed = judge(&control, Outcome::Segfault, REFUSED).expect_err("a segfault");
    assert!(crashed.contains("segfault"), "{crashed}");
    let ignored =
        "test a::b ... ignored\n\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured\n";
    let skipped = judge(&control, Outcome::Failed, ignored).expect_err("an ignored test");
    assert!(skipped.contains("exactly its one test"), "{skipped}");
    let two = "test a::b ... FAILED\ntest a::c ... boom FAILED\n\ntest result: FAILED. 0 passed; 2 failed; 0 ignored\n";
    let elsewhere = judge(&control, Outcome::Failed, two).expect_err("another test's diagnostic");
    assert!(elsewhere.contains("exactly its one test"), "{elsewhere}");
    let build = "error[E0308]: mismatched types\nerror: could not compile `dcbor`\n";
    assert!(
        judge(&control, Outcome::BuildRefused, build).is_err(),
        "a build failure"
    );
    let silent = REFUSED.replace("boom", "another assertion");
    let unnamed = judge(&control, Outcome::Failed, &silent).expect_err("no pattern");
    assert!(unnamed.contains("another rule"), "{unnamed}");
    let empty = "test result: ok. 0 passed; 0 failed; 0 ignored\n";
    assert!(
        restored(&control, Outcome::Pass, empty).is_err(),
        "nothing ran"
    );
    assert!(
        restored(&control, Outcome::Failed, REFUSED).is_err(),
        "still red"
    );
}

/// A Miri run that undefined behavior ended: libtest selected and started
/// the one test, and the interpreter's report follows, with no summary.
const UNDEFINED: &str = "running 1 test\ntest a::b ... error: Undefined Behavior: reading memory at alloc1[0x0..0x8], but memory is uninitialized\n";

/// A Miri control is refused by its own test's undefined behavior, its
/// report that test's though libtest printed no summary; restored, it ran
/// alone and passed.
#[test]
fn a_miri_control_is_refused_by_its_own_tests_undefined_behavior() {
    let control = one(MIRI);
    assert_eq!(
        judge(&control, Outcome::UndefinedBehavior, UNDEFINED),
        Ok(())
    );
    assert_eq!(restored(&control, Outcome::Pass, RESTORED), Ok(()));
}

/// Planted: a Miri run that selected another test, two tests, or none, and
/// one whose undefined behavior is not of the planned outcome, are each no
/// refusal.
#[test]
fn every_other_miri_run_is_no_refusal() {
    let control = one(MIRI);
    let other = UNDEFINED.replace("test a::b ...", "test a::c ...");
    let elsewhere = judge(&control, Outcome::UndefinedBehavior, &other).expect_err("another test");
    assert!(elsewhere.contains("exactly its one test"), "{elsewhere}");
    let two = UNDEFINED.replace("running 1 test", "running 2 tests");
    let both = judge(&control, Outcome::UndefinedBehavior, &two).expect_err("two selected");
    assert!(both.contains("exactly its one test"), "{both}");
    let none = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored\n";
    assert!(
        judge(&control, Outcome::UndefinedBehavior, none).is_err(),
        "nothing selected"
    );
    let failed = judge(&control, Outcome::Failed, UNDEFINED).expect_err("another outcome");
    assert!(
        failed.contains("where the planted defect's refusal is undefined_behavior"),
        "{failed}"
    );
}

/// A compile-time refusal is the planned outcome of its row, named in the
/// build's log; a model run naming the pattern without the planned outcome
/// is not it.
#[test]
fn a_refused_build_is_judged_by_its_log() {
    let control = one(BUILT);
    let log = "error[E0080]: evaluation of constant value failed\n  one admitted unit stores more than a quantum into retained state\n";
    assert_eq!(judge(&control, Outcome::BuildRefused, log), Ok(()));
    assert!(judge(&control, Outcome::Failed, log).is_err());
}

/// trybuild's refusal is the fixture's own: its block, under the header with
/// or without the expectation a mixed suite prints, names the pattern;
/// another fixture's block naming it is not the refusal.
#[test]
fn a_fixture_is_refused_by_its_own_block() {
    let control = one(FIXTURE);
    let annotated = "running 1 test\n\
        test tests/ui/pass/y.rs [should pass] ... ok\n\
        test tests/ui/fail/x.rs [should fail to compile] ... error\n\
        Expected test case to fail to compile, but it succeeded.\n\n\
        test suite ... FAILED\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored\n";
    assert_eq!(judge(&control, Outcome::Failed, annotated), Ok(()));
    let plain = annotated
        .replace(" [should fail to compile]", "")
        .replace(" [should pass]", "");
    assert_eq!(judge(&control, Outcome::Failed, &plain), Ok(()));
    let other = annotated.replace("fail/x.rs", "fail/y.rs");
    let elsewhere = judge(&control, Outcome::Failed, &other).expect_err("another fixture");
    assert!(elsewhere.contains("another rule"), "{elsewhere}");
}

/// The evidence of a control seen red and green with the copy restored
/// passes; the planted controls: never run, not red, not green again, a diff
/// that changed nothing and a copy left changed are each named.
#[test]
fn every_native_control_is_seen_red_then_green_in_its_restored_copy() {
    let logs = std::env::temp_dir().join(format!("dcbor-control-logs-{}", std::process::id()));
    // The native control's evidence directory, by the one definition of it.
    let native = directory(&logs, &one(NATIVE));
    std::fs::create_dir_all(&native).expect("a fixture directory");
    let write =
        |file: &str, text: &str| std::fs::write(native.join(file), text).expect("a fixture file");
    let controls = vec![one(NATIVE), one(FIXTURE)];
    write("red.judged", "refused\n");
    write("green.judged", "restored\n");
    write("before.sha256", "a\n");
    write("planted.sha256", "b\n");
    write("after.sha256", "a\n");
    assert_eq!(evidence(&controls, &logs, "nightly"), Vec::<String>::new());
    let stable = evidence(&controls, &logs, "stable");
    assert!(
        stable
            .iter()
            .any(|fault| fault.contains("t under native: never run")),
        "{stable:#?}"
    );
    // A Miri control's evidence is its own model's directory: the native
    // control's files are not it.
    let miri = vec![one(MIRI)];
    let unrun = evidence(&miri, &logs, "nightly");
    assert!(
        unrun
            .iter()
            .any(|fault| fault.contains("u under tree: never run")),
        "{unrun:#?}"
    );
    assert_eq!(directory(&logs, &miri[0]), logs.join("u-tree"));
    write(
        "red.judged",
        "c: pass, where the planted defect's refusal is failed\n",
    );
    write("after.sha256", "b\n");
    write("planted.sha256", "a\n");
    let faults = evidence(&controls, &logs, "nightly");
    std::fs::remove_dir_all(&logs).expect("the fixture removed");
    assert!(
        faults.iter().any(|fault| fault.contains("not seen red")),
        "{faults:#?}"
    );
    assert!(
        faults
            .iter()
            .any(|fault| fault.contains("changed no source")),
        "{faults:#?}"
    );
    assert!(
        faults
            .iter()
            .any(|fault| fault.contains("once the diff is reversed")),
        "{faults:#?}"
    );
}
