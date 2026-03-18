use anyhow::Result;
use serde::Deserialize;

use crate::models::{Component, Hash, ParsedSbom, SourceFormat};

/// SPDX 2.3 JSON document structure (subset we care about)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    #[allow(dead_code)]
    spdx_version: Option<String>,
    #[serde(default)]
    packages: Vec<SpdxPackage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version_info: Option<String>,
    #[serde(default)]
    supplier: Option<String>,
    #[serde(default)]
    license_concluded: Option<String>,
    #[serde(default)]
    license_declared: Option<String>,
    #[serde(default)]
    external_refs: Vec<SpdxExternalRef>,
    #[serde(default)]
    checksums: Vec<SpdxChecksum>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    #[allow(dead_code)]
    reference_category: Option<String>,
    reference_type: Option<String>,
    reference_locator: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxChecksum {
    algorithm: Option<String>,
    checksum_value: Option<String>,
}

pub fn parse_json(content: &str) -> Result<ParsedSbom> {
    let doc: SpdxDocument = serde_json::from_str(content)
        .map_err(|e| crate::errors::ShieldBomError::ParseError(format!("SPDX JSON: {e}")))?;

    let components = doc
        .packages
        .into_iter()
        .map(|pkg| {
            let cpe = pkg
                .external_refs
                .iter()
                .find(|r| r.reference_type.as_deref() == Some("cpe23Type"))
                .and_then(|r| r.reference_locator.clone());

            let purl = pkg
                .external_refs
                .iter()
                .find(|r| r.reference_type.as_deref() == Some("purl"))
                .and_then(|r| r.reference_locator.clone());

            let licenses = extract_licenses(&pkg);
            let hashes = pkg
                .checksums
                .into_iter()
                .filter_map(|c| {
                    Some(Hash {
                        algorithm: c.algorithm?,
                        value: c.checksum_value?,
                    })
                })
                .collect();

            Component {
                name: pkg.name,
                version: pkg.version_info.unwrap_or_default(),
                supplier: pkg.supplier,
                cpe,
                purl,
                licenses,
                hashes,
                source_format: SourceFormat::Spdx23Json,
            }
        })
        .collect();

    Ok(ParsedSbom {
        format_detected: SourceFormat::Spdx23Json,
        components,
    })
}

pub fn parse_tag_value(content: &str) -> Result<ParsedSbom> {
    let mut components = Vec::new();
    let mut current: Option<TagValueBuilder> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            match key {
                "PackageName" => {
                    if let Some(builder) = current.take() {
                        components.push(builder.build());
                    }
                    current = Some(TagValueBuilder::new(value.to_string()));
                }
                "PackageVersion" => {
                    if let Some(ref mut b) = current {
                        b.version = Some(value.to_string());
                    }
                }
                "PackageSupplier" => {
                    if let Some(ref mut b) = current {
                        b.supplier = Some(value.to_string());
                    }
                }
                "PackageLicenseConcluded" | "PackageLicenseDeclared" => {
                    if let Some(ref mut b) = current {
                        if value != "NOASSERTION" && value != "NONE" {
                            b.licenses.push(value.to_string());
                        }
                    }
                }
                "ExternalRef" => {
                    if let Some(ref mut b) = current {
                        let parts: Vec<&str> = value.splitn(3, ' ').collect();
                        if parts.len() == 3 {
                            match parts[1] {
                                "cpe23Type" => b.cpe = Some(parts[2].to_string()),
                                "purl" => b.purl = Some(parts[2].to_string()),
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(builder) = current {
        components.push(builder.build());
    }

    Ok(ParsedSbom {
        format_detected: SourceFormat::Spdx23TagValue,
        components,
    })
}

struct TagValueBuilder {
    name: String,
    version: Option<String>,
    supplier: Option<String>,
    cpe: Option<String>,
    purl: Option<String>,
    licenses: Vec<String>,
}

impl TagValueBuilder {
    fn new(name: String) -> Self {
        Self {
            name,
            version: None,
            supplier: None,
            cpe: None,
            purl: None,
            licenses: Vec::new(),
        }
    }

    fn build(self) -> Component {
        Component {
            name: self.name,
            version: self.version.unwrap_or_default(),
            supplier: self.supplier,
            cpe: self.cpe,
            purl: self.purl,
            licenses: self.licenses,
            hashes: Vec::new(),
            source_format: SourceFormat::Spdx23TagValue,
        }
    }
}

fn extract_licenses(pkg: &SpdxPackage) -> Vec<String> {
    let mut licenses = Vec::new();
    for lic in [&pkg.license_concluded, &pkg.license_declared].iter().copied().flatten() {
        if lic != "NOASSERTION" && lic != "NONE" {
            licenses.push(lic.clone());
        }
    }
    licenses
}
