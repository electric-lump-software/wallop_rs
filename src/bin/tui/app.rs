use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use super::input::{Action, map_key};
use super::render;
use super::state::{Mode, VerificationSession};

pub fn run(mut session: VerificationSession) -> io::Result<()> {
    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = run_loop(&mut terminal, &mut session);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    session: &mut VerificationSession,
) -> io::Result<()> {
    if session.mode == Mode::Demo {
        run_demo_loop(terminal, session)
    } else {
        run_interactive_loop(terminal, session)
    }
}

fn run_interactive_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    session: &mut VerificationSession,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| render::render(session, frame))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key_event) = event::read()? {
                if let Some(action) = map_key(key_event, session.view) {
                    match action {
                        Action::Quit => break,
                        Action::Advance => {
                            if session.all_revealed() {
                                session.toggle_detail();
                            } else {
                                session.advance();
                            }
                        }
                        Action::ContinueAll => session.continue_all(),
                        Action::StepUp => session.move_step_up(),
                        Action::StepDown => session.move_step_down(),
                        Action::NextScenario => {
                            session.next_scenario();
                        }
                        Action::PrevScenario => {
                            session.prev_scenario();
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn run_demo_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    session: &mut VerificationSession,
) -> io::Result<()> {
    let step_delay_pass = Duration::from_millis(800);
    let step_delay_fail = Duration::from_millis(1500);
    let scenario_pause = Duration::from_millis(2000);

    let total_scenarios = session.scenarios_total;
    let mut scenario_idx = 0;

    loop {
        // Animate step reveals for the current scenario
        while !session.all_revealed() {
            terminal.draw(|frame| render::render(session, frame))?;

            // Determine delay based on what the next step's status will be
            let next_step_idx = session.revealed_count;
            let delay = if next_step_idx < session.steps.len() {
                match &session.steps[next_step_idx].status {
                    wallop_verifier::verify_steps::StepStatus::Fail(_) => step_delay_fail,
                    _ => step_delay_pass,
                }
            } else {
                step_delay_pass
            };

            // Wait, but check for quit
            if wait_or_quit(delay)? {
                return Ok(());
            }

            session.advance();
        }

        // Draw the final state with all steps revealed
        terminal.draw(|frame| render::render(session, frame))?;

        // Mark current scenario result
        if scenario_idx < session.scenarios.len() {
            let has_fail = session.steps.iter().any(|s| {
                matches!(s.status, wallop_verifier::verify_steps::StepStatus::Fail(_))
            });
            session.scenarios[scenario_idx].passed = Some(!has_fail);
            if !has_fail {
                session.scenarios_passed += 1;
            }
        }

        // Redraw with updated scenario status
        terminal.draw(|frame| render::render(session, frame))?;

        // Check if this was the last scenario
        scenario_idx += 1;
        if scenario_idx >= total_scenarios {
            // Hold on summary -- wait for quit
            loop {
                terminal.draw(|frame| render::render(session, frame))?;
                if event::poll(Duration::from_millis(100))? {
                    if let Event::Key(key_event) = event::read()? {
                        if key_event.code == KeyCode::Char('q')
                            || (key_event.modifiers.contains(KeyModifiers::CONTROL)
                                && key_event.code == KeyCode::Char('c'))
                        {
                            return Ok(());
                        }
                    }
                }
            }
        }

        // Pause between scenarios
        if wait_or_quit(scenario_pause)? {
            return Ok(());
        }

        // Advance to next scenario
        session.next_scenario();
    }
}

/// Wait for `duration`, returning `true` if the user pressed 'q' or Ctrl-C.
fn wait_or_quit(duration: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        let remaining = deadline - Instant::now();
        let poll_time = remaining.min(Duration::from_millis(50));
        if event::poll(poll_time)? {
            if let Event::Key(key_event) = event::read()? {
                if key_event.code == KeyCode::Char('q')
                    || (key_event.modifiers.contains(KeyModifiers::CONTROL)
                        && key_event.code == KeyCode::Char('c'))
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
