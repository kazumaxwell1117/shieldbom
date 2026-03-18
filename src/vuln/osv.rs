use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::models::{Component, Severity, VulnMatch, VulnSource};

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    purl: String,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: Option<String>,
    score: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: Option<String>,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
}

/// Query OSV for vulnerabilities for each component that has a PURL
pub async fn query_batch(components: &[Component]) -> Result<Vec<VulnMatch>> {
    let client = reqwest::Client::new();
    let mut results = Vec::new();

    for component in components {
        let Some(purl) = &component.purl else {
            continue;
        };

        if component.version.is_empty() {
            continue;
        }

        let query = OsvQuery {
            package: OsvPackage {
                purl: purl.clone(),
            },
            version: component.version.clone(),
        };

        match client.post(OSV_API_URL).json(&query).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(osv_resp) = resp.json::<OsvResponse>().await {
                    for vuln in osv_resp.vulns {
                        results.push(convert_osv_vuln(&vuln, component));
                    }
                }
            }
            Ok(resp) => {
                tracing::warn!(
                    "OSV API returned {} for {}@{}",
                    resp.status(),
                    component.name,
                    component.version
                );
            }
            Err(e) => {
                tracing::warn!("OSV API error for {}@{}: {e}", component.name, component.version);
            }
        }
    }

    Ok(results)
}

fn convert_osv_vuln(vuln: &OsvVuln, component: &Component) -> VulnMatch {
    let (severity, cvss_score) = extract_severity(vuln);
    let fixed_version = extract_fixed_version(vuln);

    VulnMatch {
        component_name: component.name.clone(),
        component_version: component.version.clone(),
        cve_id: vuln.id.clone(),
        severity,
        cvss_score,
        source: VulnSource::Osv,
        affected_versions: String::new(),
        fixed_version,
        description: vuln.summary.clone(),
    }
}

fn extract_severity(vuln: &OsvVuln) -> (Severity, Option<f64>) {
    for sev in &vuln.severity {
        if sev.severity_type.as_deref() == Some("CVSS_V3") {
            if let Some(score_str) = &sev.score {
                // CVSS vector string: try to extract base score
                // Format: CVSS:3.1/AV:N/AC:L/... - we need to parse or just use the DB score
                // For now, try to parse if it's a plain number
                if let Ok(score) = score_str.parse::<f64>() {
                    return (Severity::from_cvss(score), Some(score));
                }
            }
        }
    }
    (Severity::Unknown, None)
}

fn extract_fixed_version(vuln: &OsvVuln) -> Option<String> {
    for affected in &vuln.affected {
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(fixed) = &event.fixed {
                    return Some(fixed.clone());
                }
            }
        }
    }
    None
}
