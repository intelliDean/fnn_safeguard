use colored::{ColoredString, Colorize};
use serde::Serialize;
use serde_json::to_string_pretty;
use std::fmt::Display;

pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    pub fn badge(&self) -> ColoredString {
        match self {
            CheckStatus::Pass => "PASS".green().bold(),
            CheckStatus::Warn => "WARN".yellow().bold(),
            CheckStatus::Fail => "FAIL".red().bold(),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        }
    }
}

pub struct TerminalReporter;

impl TerminalReporter {
    pub fn header(title: &str) {
        println!("{}", "=========================================================".cyan());
        println!("  {}", title.bold().white());
        println!("{}", "=========================================================".cyan());
    }

    pub fn section(name: &str) {
        println!("\n{}", format!("[ {} ]", name).bold().blue());
    }

    pub fn row(label: &str, value: impl Display) {
        println!("{:<28} {}", label.dimmed(), value);
    }

    pub fn status_row(label: &str, status: CheckStatus, note: Option<&str>) {
        if let Some(n) = note {
            println!("{:<28} {} ({})", label.dimmed(), status.badge(), n.dimmed());
        } else {
            println!("{:<28} {}", label.dimmed(), status.badge());
        }
    }

    pub fn footer(success: bool, msg: &str) {
        println!("{}", "---------------------------------------------------------".cyan());
        if success {
            println!("  STATUS: {}", msg.green().bold());
        } else {
            println!("  STATUS: {}", msg.red().bold());
        }
        println!("{}\n", "=========================================================".cyan());
    }

    pub fn print_json<T: Serialize>(val: &T) {
        if let Ok(json) = to_string_pretty(val) {
            println!("{}", json);
        }
    }
}

/// Helper that redacts any accidental secrets from arbitrary text.
pub fn sanitize_text(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_string();
    for secret in secrets {
        if !secret.trim().is_empty() {
            out = out.replace(secret.trim(), "[REDACTED]");
        }
    }
    out
}
