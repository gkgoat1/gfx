//! Property/contract tests that every [`Transform`] must pass (plan §5.5).
//! Exposed as public functions so builtin crates (e.g. `gfx-remap`) exercise
//! their own implementations without duplicating the harness.

use crate::event::Event;
use crate::transform::{Pipeline, Transform};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Drives `events` through a fresh `make_transform()`, then `finish`,
/// returning the full output sequence.
pub fn run_through<T, F>(make: F, events: Vec<Event>) -> Result<Vec<Event>, crate::error::Error>
where
    F: Fn() -> T,
    T: Transform + 'static,
{
    let mut p = Pipeline::builder().push(Box::new(make())).build();
    let mut out = Vec::new();
    for ev in events {
        p.apply(ev, &mut out)?;
    }
    p.finish(&mut out)?;
    Ok(out)
}

/// Determinism: two identical runs produce identical outputs.
pub fn assert_deterministic<T, F>(make: F, events: Vec<Event>)
where
    F: Fn() -> T,
    T: Transform + 'static,
{
    let a = run_through(&make, events.clone()).expect("first run");
    let b = run_through(&make, events).expect("second run");
    assert_eq!(a, b, "transform is not deterministic");
}

/// `finish` idempotence: a second `finish` yields no further events and does
/// not fail.
pub fn assert_finish_idempotent<T, F>(make: F, events: Vec<Event>)
where
    F: Fn() -> T,
    T: Transform + 'static,
{
    let mut t = make();
    let mut out = Vec::new();
    for ev in events {
        t.apply(ev, &mut out).expect("apply");
    }
    t.finish(&mut out).expect("finish #1");
    let len_after_first = out.len();
    t.finish(&mut out).expect("finish #2");
    assert_eq!(
        out.len(),
        len_after_first,
        "second finish emitted extra events"
    );
}

/// `reset` restores fresh-transform state: running events, resetting, then
/// running the same events again yields the same output as one run.
pub fn assert_reset_restores_fresh<T, F>(make: F, events: Vec<Event>)
where
    F: Fn() -> T,
    T: Transform + 'static,
{
    let fresh = run_through(&make, events.clone()).expect("fresh run");

    let mut t = make();
    let mut buf1 = Vec::new();
    for ev in &events {
        t.apply(ev.clone(), &mut buf1).expect("pass 1 apply");
    }
    t.finish(&mut buf1).expect("pass 1 finish");
    assert_eq!(buf1, fresh, "manual drive diverges from pipeline drive");

    t.reset();
    let mut buf2 = Vec::new();
    for ev in events {
        t.apply(ev, &mut buf2).expect("pass 2 apply");
    }
    t.finish(&mut buf2).expect("pass 2 finish");
    assert_eq!(buf2, fresh, "reset did not restore fresh state");
}
