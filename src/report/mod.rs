use anyhow::Result;
use clap::ValueEnum;
use colored::Colorize;
use serde::Serialize;

use crate::models::{AnalysisReport, Severity};

#[derive(Clone, ValueEnum, Default)]
pub enum OutputFormat {
    /// Human-readable terminal table
    #[default]
    Table,
    /// Machine-readable JSON
    Json,
    /// SARIF 2.1.0 format
    Sarif,
}

pub fn render(report: &AnalysisReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Table => render_table(report),
        OutputFormat::Json => render_json(report),
        OutputFormat::Sarif => render_sarif(report),
    }
}

fn render_table(report: &AnalysisReport) -> Result<()> {
    println!();
    println!("{}", "ShieldBOM Scan Results".bold().underline());
    println!("File: {}", report.sbom_file.display());
    println!("Format: {}", report.format_detected);
    println!("Components: {}", report.stats.total_components);
    println!();

    // Summary bar
    println!(
        "  {} Critical  {} High  {} Medium  {} Low",
        format_severity_count(report.stats.critical, Severity::Critical),
        format_severity_count(report.stats.high, Severity::High),
        format_severity_count(report.stats.medium, Severity::Medium),
        format_severity_count(report.stats.low, Severity::Low),
    );
    println!();

    // Vulnerabilities
    if !report.vulnerabilities.is_empty() {
        println!("{}", "Vulnerabilities".bold());
        println!("{:-<80}", "");
        for vuln in &report.vulnerabilities {
            let severity_str = match vuln.severity {
                Severity::Critical => vuln.severity.to_string().red().bold(),
                Severity::High => vuln.severity.to_string().red(),
                Severity::Medium => vuln.severity.to_string().yellow(),
                Severity::Low => vuln.severity.to_string().blue(),
                _ => vuln.severity.to_string().normal(),
            };

            println!(
                "  [{severity_str}] {} {} @ {}",
                vuln.cve_id, vuln.component_name, vuln.component_version
            );
            if !vuln.description.is_empty() {
                // Truncate long descriptions
                let desc = if vuln.description.len() > 100 {
                    format!("{}...", &vuln.description[..100])
                } else {
                    vuln.description.clone()
                };
                println!("    {}", desc.dimmed());
            }
            if let Some(fixed) = &vuln.fixed_version {
                println!("    Fix: upgrade to {}", fixed.green());
            }
        }
        println!();
    }

    // License issues
    if !report.license_issues.is_empty() {
        println!("{}", "License Issues".bold());
        println!("{:-<80}", "");
        for issue in &report.license_issues {
            println!(
                "  [{}] {} @ {} - {}",
                issue.issue_type.to_string().yellow(),
                issue.component_name,
                issue.component_version,
                issue.description
            );
        }
        println!();
    }

    if report.vulnerabilities.is_empty() && report.license_issues.is_empty() {
        println!("{}", "No issues found.".green().bold());
    }

    Ok(())
}

fn format_severity_count(count: usize, severity: Severity) -> String {
    let s = format!("{count}");
    match severity {
        Severity::Critical => format!("{}", s.red().bold()),
        Severity::High => format!("{}", s.red()),
        Severity::Medium => format!("{}", s.yellow()),
        Severity::Low => format!("{}", s.blue()),
        _ => s,
    }
}

fn render_json(report: &AnalysisReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{json}");
    Ok(())
}

fn render_sarif(report: &AnalysisReport) -> Result<()> {
    let sarif = SarifReport::from_analysis(report);
    let json = serde_json::to_string_pretty(&sarif)?;
    println!("{json}");
    Ok(())
}

/// SARIF 2.1.0 output format
#[derive(Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

impl SarifReport {
    fn from_analysis(report: &AnalysisReport) -> Self {
        let mut rules = Vec::new();
        let mut results = Vec::new();

        for vuln in &report.vulnerabilities {
            rules.push(SarifRule {
                id: vuln.cve_id.clone(),
                short_description: SarifMessage {
                    text: vuln.description.clone(),
                },
            });

            results.push(SarifResult {
                rule_id: vuln.cve_id.clone(),
                level: match vuln.severity {
                    Severity::Critical | Severity::High => "error".to_string(),
                    Severity::Medium => "warning".to_string(),
                    _ => "note".to_string(),
                },
                message: SarifMessage {
                    text: format!(
                        "{} in {} @ {} ({})",
                        vuln.cve_id, vuln.component_name, vuln.component_version, vuln.source
                    ),
                },
            });
        }

        SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "ShieldBOM".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/kazumaxwell1117/shieldbom".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}
