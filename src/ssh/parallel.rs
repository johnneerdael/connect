//! Threaded copy runtime will live here.
//!
//! The planner and job model are intentionally separated in `copy.rs` so the
//! sequential copy path can remain untouched until the executor work starts.
