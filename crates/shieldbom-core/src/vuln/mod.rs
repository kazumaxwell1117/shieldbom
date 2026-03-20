mod nvd;
mod osv;

use anyhow::Result;

use crate::models::{Component, VulnMatch};

/// Match vulnerabilities using online APIs (OSV primary, NVD optional secondary)
pub async fn match_vulnerabilities(
    components: &[Component],
    use_nvd: bool,
) -> Result<Vec<VulnMatch>> {
    let mut all_vulns = Vec::new();

    // Use OSV as primary source (PURL-native, free, no rate limit issues)
    let osv_vulns = osv::query_batch(components).await?;
    all_vulns.extend(osv_vulns);

    // Query NVD as secondary source when enabled
    if use_nvd {
        tracing::info!("Querying NVD API (this may be slow due to rate limiting)...");
        let nvd_vulns = nvd::query_batch(components).await?;
        all_vulns.extend(nvd_vulns);
    }

    // Deduplicate by CVE ID + component
    all_vulns.sort_by(|a, b| (&a.component_name, &a.cve_id).cmp(&(&b.component_name, &b.cve_id)));
    all_vulns.dedup_by(|a, b| a.component_name == b.component_name && a.cve_id == b.cve_id);

    Ok(all_vulns)
}

/// Match vulnerabilities using only the local database (offline mode)
pub async fn match_offline(components: &[Component]) -> Result<Vec<VulnMatch>> {
    crate::db::lookup_offline(components)
}
