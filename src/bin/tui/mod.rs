mod app;
mod input;
mod render;
mod state;

use std::process::ExitCode;

pub(crate) fn run_verify_tui(_path: &str, _pins: &super::PinConfig) -> ExitCode {
    eprintln!("TUI mode not yet implemented");
    ExitCode::from(2)
}

pub(crate) fn run_selftest_tui(_demo: bool) -> ExitCode {
    eprintln!("TUI mode not yet implemented");
    ExitCode::from(2)
}
