use clap::{Parser, Subcommand};
use std::io::Read;
use std::process::ExitCode;

use wallop_verifier::StepName;
use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::catalog::runner::ScenarioOutcome;
use wallop_verifier::verify_steps::{StepStatus, verify_bundle};

#[derive(Parser)]
#[command(
    name = "wallop-verify",
    version,
    about = "Verify a Wallop! proof bundle"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to proof bundle JSON file, or "-" for stdin
    path: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the tamper scenario catalog against a generated known-good bundle
    Selftest,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match (cli.command, cli.path) {
        (Some(Commands::Selftest), _) => run_selftest(),
        (None, Some(path)) => run_verify(&path),
        (None, None) => {
            eprintln!("error: no proof bundle path provided");
            eprintln!("Usage: wallop-verify <PATH> or wallop-verify selftest");
            ExitCode::from(2)
        }
    }
}

// ==================== selftest subcommand ====================

fn run_selftest() -> ExitCode {
    let version = env!("CARGO_PKG_VERSION");
    println!("wallop-verify {version} selftest");

    let report = match wallop_verifier::catalog::run_shipping_catalog() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("catalog load error: {e}");
            return ExitCode::from(3);
        }
    };

    println!();
    println!("Running {} tamper scenarios...", report.total_scenarios);
    println!();

    for result in &report.results {
        match &result.outcome {
            ScenarioOutcome::Passed { caught_at } => {
                println!("PASS: {} caught at {}", result.name, caught_at);
            }
            ScenarioOutcome::FailedP0 => {
                println!("FAIL: {} expected catch, got (no failure)", result.name);
                println!("      >>> P0: verifier accepted tampered bundle");
            }
            ScenarioOutcome::CaughtByWrongStep { expected, actual } => {
                let expected_str: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
                println!(
                    "FAIL: {} expected one of [{}], got {}",
                    result.name,
                    expected_str.join(", "),
                    actual
                );
            }
            ScenarioOutcome::MutationError(e) => {
                println!("SKIP: {} (mutation failed: {})", result.name, e);
            }
        }
    }

    println!();
    let total_step_names = StepName::all().len();
    let covered = report.covered_steps.len();
    println!("Coverage check: {covered}/{total_step_names} StepName variants covered at runtime");

    if !report.coverage_complete {
        println!();
        println!("UNCOVERED VARIANTS:");
        for variant in StepName::all() {
            if !report.covered_steps.contains(variant) {
                println!("  - {variant}");
            }
        }
    }

    println!();
    println!(
        "{} scenarios run, {} passed, {} P0 failures, {} caught by wrong step, {} skipped",
        report.total_scenarios,
        report.passed,
        report.failed_p0,
        report.caught_by_wrong_step,
        report.skipped
    );

    if report.failed_p0 > 0 {
        ExitCode::from(1)
    } else if report.caught_by_wrong_step > 0 || !report.coverage_complete {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

// ==================== verify subcommand (default) ====================

fn run_verify(path: &str) -> ExitCode {
    // Read input
    let json = match path {
        "-" => {
            let mut buf = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                eprintln!("error reading stdin: {e}");
                return ExitCode::from(2);
            }
            buf
        }
        path => match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error reading {path}: {e}");
                return ExitCode::from(2);
            }
        },
    };

    // Parse bundle
    let bundle = match ProofBundle::from_json(&json) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    // Run verification
    let report = verify_bundle(&bundle);

    // Print header
    let version = env!("CARGO_PKG_VERSION");
    println!("wallop-verify {version}");
    println!();
    println!("  Draw ................ {}", &bundle.draw_id);
    if let Some(ref kid) = report.operator_key_id {
        println!("  Operator key ........ {kid}");
    }
    if let Some(ref kid) = report.infra_key_id {
        println!("  Infrastructure key .. {kid}");
    }
    println!();

    // Print steps
    for step in &report.steps {
        let name_str = step.name.to_string();
        let dots = ".".repeat(30_usize.saturating_sub(name_str.len()));
        match &step.status {
            StepStatus::Pass => println!("  {} {} PASS", name_str, dots),
            StepStatus::Fail(reason) => println!("  {} {} FAIL ({})", name_str, dots, reason),
            StepStatus::Skip(reason) => println!("  {} {} SKIP ({})", name_str, dots, reason),
        }
    }

    println!();

    // Belt-and-suspenders: run verify_full()
    let belt_check = run_verify_full_check(&bundle);

    if report.passed() && belt_check {
        println!("  RESULT: PASS");
        ExitCode::SUCCESS
    } else if report.passed() && !belt_check {
        eprintln!("  WARNING: step-by-step passed but verify_full() disagrees — possible drift");
        ExitCode::from(1)
    } else {
        println!("  RESULT: FAIL ({} errors)", report.error_count());
        ExitCode::from(1)
    }
}

fn run_verify_full_check(bundle: &ProofBundle) -> bool {
    let entries: Vec<wallop_verifier::Entry> = bundle
        .entries
        .iter()
        .map(|e| wallop_verifier::Entry {
            id: e.id.clone(),
            weight: e.weight,
        })
        .collect();

    let lock_sig = match hex::decode(&bundle.lock_receipt.signature_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
    {
        Some(s) => s,
        None => return false,
    };
    let op_pk = match hex::decode(&bundle.lock_receipt.public_key_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(k) => k,
        None => return false,
    };
    let exec_sig = match hex::decode(&bundle.execution_receipt.signature_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
    {
        Some(s) => s,
        None => return false,
    };
    let infra_pk = match hex::decode(&bundle.execution_receipt.public_key_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(k) => k,
        None => return false,
    };

    wallop_verifier::verify_full(
        &bundle.lock_receipt.payload_jcs,
        &lock_sig,
        &op_pk,
        &bundle.execution_receipt.payload_jcs,
        &exec_sig,
        &infra_pk,
        &entries,
    )
    .unwrap_or_default()
}
