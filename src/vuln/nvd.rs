use std::env;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;

use crate::models::{Component, Severity, VulnMatch, VulnSource};

const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Rate limit: 5 req/30s without key, 50 req/30s with key.
/// We use a conservative per-request delay to stay within limits.
const DELAY_WITHOUT_KEY: Duration = Duration::from_millis(6500); // ~4.6 req/30s
const DELAY_WITH_KEY: Duration = Duration::from_millis(650);     // ~46 req/30s

// -- NVD API 2.0 response structures --

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default, rename = "resultsPerPage")]
    results_per_page: u32,
    #[serde(default, rename = "totalResults")]
    total_results: u32,
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnWrapper>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnWrapper {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: NvdMetrics,
}

#[derive(Debug, Default, Deserialize)]
struct NvdMetrics {
    #[serde(default, rename = "cvssMetricV31")]
    cvss_v31: Vec<NvdCvssV31>,
    #[serde(default, rename = "cvssMetricV30")]
    cvss_v30: Vec<NvdCvssV30>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssV31 {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct NvdCvssV30 {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct CvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

/// Query NVD API 2.0 for vulnerabilities matching the given components.
///
/// Uses CPE match when a component has a `cpe` field, otherwise falls back
/// to keyword search by package name.
pub async fn query_batch(components: &[Component]) -> Result<Vec<VulnMatch>> {
    let api_key = env::var("SHIELDBOM_NVD_API_KEY").ok();
    let delay = if api_key.is_some() {
        DELAY_WITH_KEY
    } else {
        DELAY_WITHOUT_KEY
    };

    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(ref key) = api_key {
        if let Ok(val) = reqwest::header::HeaderValue::from_str(key) {
            headers.insert("apiKey", val);
        }
    }

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut results = Vec::new();

    for (i, component) in components.iter().enumerate() {
        if component.version.is_empty() {
            continue;
        }

        // Rate-limit: wait between requests (skip delay before the first)
        if i > 0 {
            tokio::time::sleep(delay).await;
        }

        let vulns = if let Some(cpe) = &component.cpe {
            query_by_cpe(&client, cpe, component).await
        } else {
            query_by_keyword(&client, &component.name, component).await
        };

        match vulns {
            Ok(v) => results.extend(v),
            Err(e) => {
                tracing::warn!(
                    "NVD API error for {}@{}: {e}",
                    component.name,
                    component.version
                );
            }
        }
    }

    Ok(results)
}

async fn query_by_cpe(
    client: &reqwest::Client,
    cpe: &str,
    component: &Component,
) -> Result<Vec<VulnMatch>> {
    let url = format!("{}?cpeName={}", NVD_API_URL, cpe);
    fetch_and_convert(client, &url, component).await
}

async fn query_by_keyword(
    client: &reqwest::Client,
    keyword: &str,
    component: &Component,
) -> Result<Vec<VulnMatch>> {
    let url = format!("{}?keywordSearch={}", NVD_API_URL, keyword);
    fetch_and_convert(client, &url, component).await
}

async fn fetch_and_convert(
    client: &reqwest::Client,
    url: &str,
    component: &Component,
) -> Result<Vec<VulnMatch>> {
    let resp = client.get(url).send().await?;

    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        tracing::warn!(
            "NVD rate limit hit for {}@{}, skipping",
            component.name,
            component.version
        );
        return Ok(Vec::new());
    }

    if resp.status() == reqwest::StatusCode::FORBIDDEN {
        tracing::warn!("NVD API returned 403 - check your API key");
        return Ok(Vec::new());
    }

    if !resp.status().is_success() {
        tracing::warn!(
            "NVD API returned {} for {}@{}",
            resp.status(),
            component.name,
            component.version
        );
        return Ok(Vec::new());
    }

    let nvd_resp: NvdResponse = resp.json().await?;
    let mut results = Vec::new();

    for wrapper in &nvd_resp.vulnerabilities {
        results.push(convert_nvd_cve(&wrapper.cve, component));
    }

    Ok(results)
}

fn convert_nvd_cve(cve: &NvdCve, component: &Component) -> VulnMatch {
    let (severity, cvss_score) = extract_severity(cve);
    let description = extract_description(cve);

    VulnMatch {
        component_name: component.name.clone(),
        component_version: component.version.clone(),
        cve_id: cve.id.clone(),
        severity,
        cvss_score,
        source: VulnSource::Nvd,
        affected_versions: String::new(),
        fixed_version: None,
        description,
    }
}

fn extract_severity(cve: &NvdCve) -> (Severity, Option<f64>) {
    // Prefer CVSS v3.1, fall back to v3.0
    if let Some(metric) = cve.metrics.cvss_v31.first() {
        let score = metric.cvss_data.base_score;
        return (Severity::from_cvss(score), Some(score));
    }
    if let Some(metric) = cve.metrics.cvss_v30.first() {
        let score = metric.cvss_data.base_score;
        return (Severity::from_cvss(score), Some(score));
    }
    (Severity::Unknown, None)
}

fn extract_description(cve: &NvdCve) -> String {
    // Prefer English description
    cve.descriptions
        .iter()
        .find(|d| d.lang == "en")
        .or_else(|| cve.descriptions.first())
        .map(|d| d.value.clone())
        .unwrap_or_default()
}
