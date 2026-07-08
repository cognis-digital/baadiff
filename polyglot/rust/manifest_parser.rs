use regex::{Regex, Captures};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

// ============================================================================
// Error Types and Result Definitions
// ============================================================================

#[derive(Error, Debug)]
pub enum ManifestParserError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON/YAML parse error: {0}")]
    Parse(String),

    #[error("Pattern match failed for rule: {rule}, offset: {offset}")]
    PatternMatch {
        rule: String,
        offset: usize,
    },

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Unknown manifest format: {path}")]
    UnknownFormat { path: PathBuf },
}

pub type Result<T> = std::result::Result<T, ManifestParserError>;

// ============================================================================
// HIPAA Rule Definitions (Business Associate Readiness)
// ============================================================================

#[derive(Debug, Clone)]
pub struct HipaaRule {
    pub id: String,
    pub domain: DomainType,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: SeverityLevel,
    pub patterns: Vec<Pattern>,
}

#[derive(Debug, Clone)]
pub enum DomainType {
    Administrative,
    Physical,
    Technical,
    Organizational,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeverityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            SeverityLevel::Info => "INFO",
            SeverityLevel::Low => "LOW",
            SeverityLevel::Medium => "MEDIUM",
            SeverityLevel::High => "HIGH",
            SeverityLevel::Critical => "CRITICAL",
        }
    }

    pub fn weight(&self) -> u8 {
        match self {
            SeverityLevel::Info => 1,
            SeverityLevel::Low => 2,
            SeverityLevel::Medium => 5,
            SeverityLevel::High => 10,
            SeverityLevel::Critical => 25,
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            SeverityLevel::Info | SeverityLevel::Low => "\x1b[36m", // cyan
            SeverityLevel::Medium => "\x1b[33m", // yellow
            SeverityLevel::High | SeverityLevel::Critical => "\x1b[31m", // red
        }
    }

    pub fn reset(&self) -> &'static str {
        "\x1b[0m"
    }
}

#[derive(Debug, Clone)]
pub struct Pattern {
    pub regex: Regex,
    pub rule_id: String,
    pub description: String,
    pub default_severity: SeverityLevel,
}

// ============================================================================
// Manifest Content and Parsed Data Structures
// ============================================================================

#[derive(Debug, Default)]
pub struct ManifestContent {
    pub raw_content: String,
    pub file_path: PathBuf,
    pub detected_format: Option<ManifestFormat>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ManifestFormat {
    Unknown,
    TerraformHcl,
    TerraformJson,
    CloudFormationYaml,
    CloudFormationJson,
    KubernetesYaml,
    CargoToml,
    NpmPkgJson,
    PipRequirementsTxt,
    Dockerfile,
    GenericText,
}

#[derive(Debug)]
pub struct ManifestMetadata {
    pub file_path: PathBuf,
    pub format: ManifestFormat,
    pub size_bytes: u64,
    pub detected_services: Vec<String>,
    pub cloud_providers: HashSet<String>,
    pub languages: HashSet<String>,
}

// ============================================================================
// Rule Registry (The Brain of baadiff)
// ============================================================================

pub struct RuleRegistry {
    rules: Vec<HipaaRule>,
}

impl Default for RuleRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.register_administrative_rules();
        registry.register_physical_rules();
        registry.register_technical_rules();
        registry.register_organizational_rules();
        registry
    }

    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn register(&mut self, rule: HipaaRule) {
        self.rules.push(rule);
    }

    pub fn get_by_id(&self, id: &str) -> Option<&HipaaRule> {
        self.rules.iter().find(|r| r.id == id).copied()
    }

    pub fn find_matches(&self, content: &str) -> Vec<MatchedRule> {
        let mut matches = Vec::new();

        for rule in &self.rules {
            for pattern in &rule.patterns {
                if let Some(captures) = pattern.regex.find(content) {
                    matches.push(MatchedRule {
                        rule: rule.clone(),
                        match_start: captures.start(0),
                        match_end: captures.end(0),
                        matched_text: content[captures.start(0)..captures.end(0)].to_string(),
                    });
                }
            }
        }

        matches.sort_by_key(|m| m.match_start);
        matches.dedup(); // Remove duplicate matches at same position

        matches
    }

    pub fn get_all_rules(&self) -> &[HipaaRule] {
        &self.rules
    }

    pub fn total_rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl RuleRegistry {
    fn register_administrative_rules(&mut self) {
        // A.1 - Risk Analysis and Assessment
        self.register(HipaaRule {
            id: "HIPAA-A-001".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Analysis",
            description: "Documented risk analysis of electronic PHI (ePHI) systems",
            severity: SeverityLevel::High,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*[:=]\s*analysis").unwrap(),
                    rule_id: "HIPAA-A-001".to_string(),
                    description: "Risk analysis keyword detected",
                    default_severity: SeverityLevel::Medium,
                },
                Pattern {
                    regex: Regex::new(r"risk\s+assessment").unwrap(),
                    rule_id: "HIPAA-A-001".to_string(),
                    description: "Risk assessment keyword detected",
                    default_severity: SeverityLevel::Medium,
                },
            ],
        });

        // A.2 - Risk Management
        self.register(HipaaRule {
            id: "HIPAA-A-002".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Management",
            description: "Controls to manage identified risks",
            severity: SeverityLevel::High,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*management").unwrap(),
                    rule_id: "HIPAA-A-002".to_string(),
                    description: "Risk management keyword detected",
                    default_severity: SeverityLevel::Medium,
                },
            ],
        });

        // A.3 - Risk Avoidance and Minimization
        self.register(HipaaRule {
            id: "HIPAA-A-003".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Avoidance",
            description: "Strategies to avoid or minimize risk",
            severity: SeverityLevel::Medium,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*avoidance").unwrap(),
                    rule_id: "HIPAA-A-003".to_string(),
                    description: "Risk avoidance keyword detected",
                    default_severity: SeverityLevel::Low,
                },
            ],
        });

        // A.4 - Risk Acceptance and Allocation
        self.register(HipaaRule {
            id: "HIPAA-A-004".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Acceptance",
            description: "Formal risk acceptance documentation",
            severity: SeverityLevel::Medium,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*acceptance").unwrap(),
                    rule_id: "HIPAA-A-004".to_string(),
                    description: "Risk acceptance keyword detected",
                    default_severity: SeverityLevel::Low,
                },
            ],
        });

        // A.5 - Risk Control
        self.register(HipaaRule {
            id: "HIPAA-A-005".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Control",
            description: "Active controls for risk management",
            severity: SeverityLevel::High,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*control").unwrap(),
                    rule_id: "HIPAA-A-005".to_string(),
                    description: "Risk control keyword detected",
                    default_severity: SeverityLevel::Medium,
                },
            ],
        });

        // A.6 - Risk Evaluation
        self.register(HipaaRule {
            id: "HIPAA-A-006".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Evaluation",
            description: "Ongoing risk evaluation processes",
            severity: SeverityLevel::Medium,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*evaluation").unwrap(),
                    rule_id: "HIPAA-A-006".to_string(),
                    description: "Risk evaluation keyword detected",
                    default_severity: SeverityLevel::Low,
                },
            ],
        });

        // A.7 - Risk Monitoring
        self.register(HipaaRule {
            id: "HIPAA-A-007".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Monitoring",
            description: "Continuous risk monitoring mechanisms",
            severity: SeverityLevel::High,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*monitoring").unwrap(),
                    rule_id: "HIPAA-A-007".to_string(),
                    description: "Risk monitoring keyword detected",
                    default_severity: SeverityLevel::Medium,
                },
            ],
        });

        // A.8 - Risk Review and Update
        self.register(HipaaRule {
            id: "HIPAA-A-008".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Review",
            description: "Periodic risk review schedules",
            severity: SeverityLevel::Medium,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*review").unwrap(),
                    rule_id: "HIPAA-A-008".to_string(),
                    description: "Risk review keyword detected",
                    default_severity: SeverityLevel::Low,
                },
            ],
        });

        // A.9 - Risk Communication
        self.register(HipaaRule {
            id: "HIPAA-A-009".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Communication",
            description: "Internal and external risk communication",
            severity: SeverityLevel::Low,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*communication").unwrap(),
                    rule_id: "HIPAA-A-009".to_string(),
                    description: "Risk communication keyword detected",
                    default_severity: SeverityLevel::Info,
                },
            ],
        });

        // A.10 - Risk Training
        self.register(HipaaRule {
            id: "HIPAA-A-010".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Training",
            description: "Staff training on risk management",
            severity: SeverityLevel::Medium,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*training").unwrap(),
                    rule_id: "HIPAA-A-010".to_string(),
                    description: "Risk training keyword detected",
                    default_severity: SeverityLevel::Low,
                },
            ],
        });

        // A.11 - Risk Authorization and Approval
        self.register(HipaaRule {
            id: "HIPAA-A-011".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Authorization",
            description: "Formal authorization for risk acceptance",
            severity: SeverityLevel::High,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*authorization").unwrap(),
                    rule_id: "HIPAA-A-011".to_string(),
                    description: "Risk authorization keyword detected",
                    default_severity: SeverityLevel::Medium,
                },
            ],
        });

        // A.12 - Risk Documentation
        self.register(HipaaRule {
            id: "HIPAA-A-012".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Documentation",
            description: "Comprehensive risk documentation",
            severity: SeverityLevel::Medium,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*documentation").unwrap(),
                    rule_id: "HIPAA-A-012".to_string(),
                    description: "Risk documentation keyword detected",
                    default_severity: SeverityLevel::Low,
                },
            ],
        });

        // A.13 - Risk Reporting
        self.register(HipaaRule {
            id: "HIPAA-A-013".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Reporting",
            description: "Regular risk reporting mechanisms",
            severity: SeverityLevel::Low,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*report").unwrap(),
                    rule_id: "HIPAA-A-013".to_string(),
                    description: "Risk report keyword detected",
                    default_severity: SeverityLevel::Info,
                },
            ],
        });

        // A.14 - Risk Metrics and KPIs
        self.register(HipaaRule {
            id: "HIPAA-A-014".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Metrics",
            description: "Quantitative risk metrics tracking",
            severity: SeverityLevel::Medium,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*metric").unwrap(),
                    rule_id: "HIPAA-A-014".to_string(),
                    description: "Risk metric keyword detected",
                    default_severity: SeverityLevel::Low,
                },
            ],
        });

        // A.15 - Risk Governance
        self.register(HipaaRule {
            id: "HIPAA-A-015".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Governance",
            description: "Governance framework for risk management",
            severity: SeverityLevel::High,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*governance").unwrap(),
                    rule_id: "HIPAA-A-015".to_string(),
                    description: "Risk governance keyword detected",
                    default_severity: SeverityLevel::Medium,
                },
            ],
        });

        // A.16 - Risk Policy and Procedures
        self.register(HipaaRule {
            id: "HIPAA-A-016".to_string(),
            domain: DomainType::Administrative,
            name: "Risk Policies",
            description: "Formal risk policies and procedures",
            severity: SeverityLevel::High,
            patterns: vec![
                Pattern {
                    regex: Regex::new(r"risk\s*policy").unwrap(),
                    rule_id: "HIPAA-A-016".to_string(),
                    description: "Risk policy keyword detected",
                    default_severity: SeverityLevel