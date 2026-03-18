mod cli;
mod models;
mod parser;
mod vuln;
mod license;
mod report;
mod db;
mod errors;

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
    use anyhow::Result;
    use crate::cli::{ScanArgs, ValidateArgs, DbArgs, DbCommands};
    use crate::parser;
    use crate::vuln;
    use crate::license;
    use crate::report;
    use crate::report::OutputFormat;

    pub async fn scan(args: ScanArgs) -> Result<()> {
        let sbom = parser::parse_sbom(&args.file)?;
        eprintln!(
            "Parsed {} components from {:?} ({})",
            sbom.components.len(),
            args.file,
            sbom.format_detected
        );

        let vulns = if args.offline {
            vuln::match_offline(&sbom.components).await?
        } else {
            vuln::match_vulnerabilities(&sbom.components, args.nvd).await?
        };
        eprintln!("Found {} vulnerabilities", vulns.len());

        let license_issues = license::check(&sbom.components);
        eprintln!("Found {} license issues", license_issues.len());

        let analysis = crate::models::AnalysisReport::new(
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
                println!("Valid {} with {} components", sbom.format_detected, sbom.components.len());
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
                crate::db::update().await?;
                eprintln!("Database updated successfully.");
                Ok(())
            }
            DbCommands::Info => {
                let info = crate::db::info()?;
                println!("{info}");
                Ok(())
            }
        }
    }
}
