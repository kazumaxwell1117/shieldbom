mod cli;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => commands::scan(args).await,
        Commands::Validate(args) => commands::validate(args),
        Commands::Db(args) => commands::db(args).await,
        Commands::Version => {
            println!("shieldbom {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

mod commands {
    use crate::cli::{DbArgs, DbCommands, ScanArgs, ValidateArgs};
    use shieldbom_core::license;
    use shieldbom_core::parser;
    use shieldbom_core::report;
    use shieldbom_core::report::OutputFormat;
    use shieldbom_core::vuln;
    use anyhow::Result;

    pub async fn scan(args: ScanArgs) -> Result<()> {
        let sbom = match parser::parse_sbom(&args.file) {
            Ok(sbom) => sbom,
            Err(e) => {
                eprintln!("Error: {e:#}");
                std::process::exit(2);
            }
        };
        eprintln!(
            "Parsed {} components from {:?} ({})",
            sbom.components.len(),
            args.file,
            sbom.format_detected
        );

        if sbom.components.is_empty() {
            eprintln!(
                "Warning: No components found in SBOM file. The file may be malformed or empty."
            );
            std::process::exit(2);
        }

        let vulns = if args.offline {
            vuln::match_offline(&sbom.components).await?
        } else {
            vuln::match_vulnerabilities(&sbom.components, args.nvd).await?
        };
        eprintln!("Found {} vulnerabilities", vulns.len());

        let license_issues = license::check(&sbom.components);
        eprintln!("Found {} license issues", license_issues.len());

        let analysis = shieldbom_core::models::AnalysisReport::new(
            args.file.clone(),
            sbom.format_detected,
            sbom.components,
            vulns,
            license_issues,
        );

        let severity = args.severity_threshold();
        let format = args.format.unwrap_or(OutputFormat::Table);
        report::render(&analysis, format)?;

        let exit_code = analysis.exit_code(&severity);
        if exit_code != 0 {
            std::process::exit(exit_code);
        }

        Ok(())
    }

    pub fn validate(args: ValidateArgs) -> Result<()> {
        match parser::parse_sbom(&args.file) {
            Ok(sbom) => {
                println!(
                    "Valid {} with {} components",
                    sbom.format_detected,
                    sbom.components.len()
                );
                Ok(())
            }
            Err(e) => {
                eprintln!("Validation failed: {e}");
                std::process::exit(2);
            }
        }
    }

    pub async fn db(args: DbArgs) -> Result<()> {
        match args.command {
            DbCommands::Update => {
                eprintln!("Updating vulnerability database...");
                shieldbom_core::db::update().await?;
                eprintln!("Database updated successfully.");
                Ok(())
            }
            DbCommands::Info => {
                let info = shieldbom_core::db::info()?;
                println!("{info}");
                Ok(())
            }
        }
    }
}
