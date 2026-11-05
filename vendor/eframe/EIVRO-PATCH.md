# Eivro Windows backport

Base: the unmodified crates.io `eframe 0.33.3` package, SHA-256
`457481173e6db5ca9fa2be93a58df8f4c7be639587aeb4853b526c6cf87db4e6`.
Upstream MIT/Apache-2.0 licenses are retained.

Only Windows behavior in `src/native/run.rs` is changed:

- Process explicitly requested updates for hidden/minimized windows, which do
  not receive Windows paint events. This lets a tray action show the window.
- Request redraw without entering a busy poll, and explicitly return to a
  sleeping event loop after the last scheduled update.

These are backports of the behavior documented in upstream issues
[5229](https://github.com/emilk/egui/issues/5229) / PR 7905 and
[8326](https://github.com/emilk/egui/issues/8326) / PR 8398.
The rest of the crate is unchanged. Non-Windows behavior is unchanged.
Remove this local override when upgrading the complete egui stack to a version
containing both fixes; do not edit Cargo's shared registry cache.

Runtime regression: in an installed Windows build, connect, hide to tray,
leave idle for 30 seconds, reopen using the tray and a second launch, then quit.
Verify bounded CPU use, pending connection events and normal network cleanup.
