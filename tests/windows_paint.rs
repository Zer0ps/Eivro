#![cfg(feature = "gui")]

// Exercise the exact Windows presentation policy on every desktop CI runner.
use eframe::egui;
#[path = "../vendor/eframe/src/native/software_frame.rs"]
mod software_frame;
