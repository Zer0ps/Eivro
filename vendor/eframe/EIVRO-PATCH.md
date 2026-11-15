# Eivro Windows backport

Base: the unmodified crates.io `eframe 0.33.3` package, SHA-256
`457481173e6db5ca9fa2be93a58df8f4c7be639587aeb4853b526c6cf87db4e6`.
Upstream MIT/Apache-2.0 licenses are retained.

The Windows event loop in `src/native/run.rs` includes two upstream fixes.

- Process explicitly requested updates for hidden/minimized windows, which do
  not receive Windows paint events. This lets a tray action show the window.
- Request redraw without entering a busy poll, and explicitly return to a
  sleeping event loop after the last scheduled update.

These are backports of the behavior documented in upstream issues
[5229](https://github.com/emilk/egui/issues/5229) / PR 7905 and
[8326](https://github.com/emilk/egui/issues/8326) / PR 8398.

Eivro additionally enables the `eivro-windows-ui` feature on its Windows WGPU
build. Its widgets use absolute pointer positions. The WGPU backend opts out
of raw device notifications and continues processing ordinary window events.
On a DXGI software adapter only, it compares the root window's shapes and
surface parameters after egui has processed the input. Matching output can
reuse the DWM image. Damaged windows, changed textures, screenshots and
externally painted content use the full render path. An unsuccessful surface
acquisition invalidates the saved frame. See the [Win32 WM_PAINT remarks](https://learn.microsoft.com/en-us/windows/win32/gdi/wm-paint).

On upgrade, review the event loop backports separately from the software GPU
optimization. Run `cargo test --test windows_paint` in the Eivro checkout.

Runtime regression: in an installed Windows build, connect, hide to tray,
leave idle for 30 seconds, reopen using the tray and a second launch, then quit.
Verify bounded CPU use, pending connection events and normal network cleanup.
