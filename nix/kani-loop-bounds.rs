// The installed Kani's check of harness-scoped loop bounds (`--loop-bounds`,
// nix/kani-driver-loop-bounds.patch), run by the bundle's install check
// (flake.nix, `kaniBundle`). One loop of at most three body executions under
// a harness bound of eight. CBMC counts a loop's backward goto and stops at
// the arrival whose count reaches the bound (goto-symex/symex_goto.cpp,
// goto-checker/symex_bmc.cpp `should_stop_unwind`), asserting there that the
// goto is not taken: three body executions take the backedge three times and
// then evaluate the exit, so a local bound of 4 must verify every property,
// and a local bound of 3 must fail on that loop's unwinding assertion alone,
// which shows the local bound reached CBMC for that loop and was checked, not
// assumed. A second harness, which no harness entry bounds, runs under its
// harness bound alone: its loop is discovered and recorded all the same, and
// its solver runs with no local bound; under a function-scoped bound of
// sum_to's loop, that harness alone, whose binary holds sum_to, resolves it.

fn count_up(n: u8) -> u8 {
    let mut i = 0;
    while i < n {
        i += 1;
    }
    i
}

#[kani::proof]
#[kani::unwind(8)]
fn counts_to_its_limit() {
    let n: u8 = kani::any();
    kani::assume(n <= 3);
    assert_eq!(count_up(n), n);
}

fn sum_to(n: u8) -> u16 {
    let mut total = 0u16;
    let mut i = 0u8;
    while i < n {
        i += 1;
        total += u16::from(i);
    }
    total
}

#[kani::proof]
#[kani::unwind(8)]
fn sums_without_a_local_bound() {
    let n: u8 = kani::any();
    kani::assume(n <= 3);
    assert!(sum_to(n) <= 6);
}
