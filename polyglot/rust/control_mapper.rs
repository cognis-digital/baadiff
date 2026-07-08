use std::collections::{HashMap, HashSet};
use std::fmt;
use regex::RegexBuilder;

/// Control ID format: e.g., "S-ADM-001" (Administrative, sub-category 001)
#[derive(Debug, Clone, PartialEq)]
pub struct Control {
    pub id: String,
    pub category: Category,
    pub description: String,
    /// Regex pattern to match against resource names/attributes
    pub patterns: Vec<Pattern>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Category {
    Administrative,
    Physical,
    Technical,
    Organizational,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::Administrative => write!(f, "ADM"),
            Category::Physical => write!(f, "PHY"),
            Category::Technical => write!(f, "TEC"),
            Category::Organizational => write!(f, "ORG"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Pattern {
    /// Exact string match
    Literal(String),
    /// Regex pattern (case-insensitive by default)
    Regex(Regex),
    /// Key-value constraint (e.g., "encrypted: true")
    KeyValue(String, String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Critical,  // Must have evidence
    High,      // Strongly recommended
    Medium,    // Good to have
    Low,       // Nice to have
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

/// A single finding: what the mapper discovered about a control.
#[derive(Debug, Clone)]
pub enum Finding {
    /// Control satisfied with evidence
    Satisfied(ControlEvidence),
    /// Partially satisfied - some requirements met
    Partial(ControlEvidence),
    /// Not found / not applicable
    NotFound(Reason),
}

/// Evidence supporting a finding.
#[derive(Debug, Clone)]
pub struct ControlEvidence {
    pub resource_id: String,
    pub attributes: HashMap<String, String>,
    pub matches: Vec<PatternMatch>,
}

impl fmt::Display for ControlEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Resource: {}", self.resource_id)?;
        if !self.attributes.is_empty() {
            writeln!(f)?;
            for (k, v) in &self.attributes {
                writeln!(f, "  - {}: {}", k, v)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern: String,
    pub matched_value: Option<String>,
}

/// Why a control wasn't found.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Reason {
    ResourceNotFound,
    AttributeMissing(String),
    PatternMismatch,
    NotApplicable,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::ResourceNotFound => write!(f, "resource not found"),
            Reason::AttributeMissing(attr) => write!(f, "missing attribute '{}'", attr),
            Reason::PatternMismatch => write!(f, "pattern mismatch"),
            Reason::NotApplicable => write!(f, "not applicable"),
        }
    }
}

/// Aggregated scorecard for all controls.
#[derive(Debug, Clone)]
pub struct Scorecard {
    pub total_controls: usize,
    pub satisfied: usize,
    pub partial: usize,
    pub not_found: usize,
    pub readiness_score: f32,  // 0-100
    pub by_category: HashMap<Category, CategoryScore>,
}

#[derive(Debug, Clone)]
pub struct CategoryScore {
    pub category: Category,
    pub total: usize,
    pub satisfied: usize,
    pub partial: usize,
    pub not_found: usize,
}

impl Scorecard {
    /// Calculate readiness score as percentage of controls with evidence.
    pub fn calculate(&self) -> f32 {
        let total_with_evidence = self.satisfied + self.partial;
        if self.total_controls == 0 {
            return 100.0;
        }
        (total_with_evidence as f32 / self.total_controls as f32) * 100.0
    }

    pub fn new(total: usize, satisfied: usize, partial: usize, not_found: usize) -> Self {
        let total_evidence = satisfied + partial;
        let readiness = if total == 0 { 100.0 } else { (total_evidence as f32 / total as f32) * 100.0 };

        Scorecard {
            total_controls: total,
            satisfied,
            partial,
            not_found,
            readiness_score: readiness,
            by_category: HashMap::new(),
        }
    }
}

impl fmt::Display for Scorecard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "HIPAA Business Associate Readiness Scorecard")?;
        writeln!(f, "=============================================")?;
        writeln!(f)?;
        writeln!(f, "Overall Readiness: {:.1}%", self.readiness_score)?;
        writeln!(f)?;
        writeln!(f, "Summary:")?;
        writeln!(f, "  Total Controls: {}", self.total_controls)?;
        writeln!(f, "  Satisfied:     {}", self.satisfied)?;
        writeln!(f, "  Partial:       {}", self.partial)?;
        writeln!(f, "  Not Found:     {}", self.not_found)?;
        writeln!(f)?;

        if !self.by_category.is_empty() {
            writeln!(f, "By Category:")?;
            for (cat, score) in &self.by_category {
                let pct = if score.total == 0 { 100.0 } else {
                    (score.satisfied as f32 + score.partial as f32) / score.total as f32 * 100.0
                };
                writeln!(f, "  {}: {:.1}% ({}/{})", cat, pct, score.satisfied + score.partial, score.total)?;
            }
        }

        Ok(())
    }
}

/// Builder for control definitions.
pub struct ControlBuilder {
    id: String,
    category: Category,
    description: String,
    patterns: Vec<Pattern>,
    severity: Severity,
}

impl ControlBuilder {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            category: Category::Administrative,
            description: String::new(),
            patterns: Vec::new(),
            severity: Severity::Medium,
        }
    }

    pub fn with_category(mut self, cat: Category) -> Self {
        self.category = cat;
        self
    }

    pub fn with_description<D>(mut self, desc: D) -> Self
    where
        D: Into<String>,
    {
        self.description = desc.into();
        self
    }

    pub fn add_literal_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.patterns.push(Pattern::Literal(pattern.into()));
        self
    }

    pub fn add_regex_pattern<R>(mut self, pattern: R) -> Self
    where
        R: Into<Regex>,
    {
        self.patterns.push(Pattern::Regex(pattern.into()));
        self
    }

    pub fn add_key_value_pattern(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.patterns.push(Pattern::KeyValue(key.into(), value.into()));
        self
    }

    pub fn with_severity(mut self, sev: Severity) -> Self {
        self.severity = sev;
        self
    }

    pub fn build(self) -> Control {
        Control {
            id: self.id,
            category: self.category,
            description: self.description,
            patterns: self.patterns,
            severity: self.severity,
        }
    }
}

/// Default HIPAA control definitions.
pub fn default_controls() -> Vec<Control> {
    vec![
        // Administrative Safeguards - Risk Analysis & Management
        ControlBuilder::new("S-ADM-001")
            .with_category(Category::Administrative)
            .add_literal_pattern("risk.analysis")
            .add_literal_pattern("threat.identification")
            .build(),

        ControlBuilder::new("S-ADM-002")
            .with_category(Category::Administrative)
            .add_literal_pattern("access.control.policy")
            .add_literal_pattern("unique.id")
            .build(),

        // Technical Safeguards - Access Control
        ControlBuilder::new("S-TEC-001")
            .with_category(Category::Technical)
            .add_literal_pattern("encryption.at.rest")
            .add_literal_pattern("encryption.in.transit")
            .build(),

        ControlBuilder::new("S-TEC-002")
            .with_category(Category::Technical)
            .add_key_value_pattern("authentication", "required: true")
            .add_key_value_pattern("mfa.enabled", "true")
            .build(),

        // Physical Safeguards - Facility Access
        ControlBuilder::new("S-PHY-001")
            .with_category(Category::Physical)
            .add_literal_pattern("facility.access.control")
            .add_literal_pattern("security.zones")
            .build(),

        // Organizational Safeguards - Business Associate Agreement
        ControlBuilder::new("S-ORG-001")
            .with_category(Category::Organizational)
            .add_literal_pattern("business.associate.agreement")
            .add_literal_pattern("third.party.audit")
            .build(),

        // Infrastructure-specific patterns
        ControlBuilder::new("INFRA-001")
            .with_category(Category::Technical)
            .add_key_value_pattern("provider", "aws|azure|gcp")
            .add_literal_pattern("vpc.cidr")
            .build(),

        ControlBuilder::new("INFRA-002")
            .with_category(Category::Technical)
            .add_literal_pattern("iam.role.assume")
            .add_literal_pattern("service.account")
            .build(),
    ]
}

/// Result of checking a single resource against all controls.
pub struct ResourceCheckResult {
    pub resource_id: String,
    pub findings: Vec<Finding>,
}

impl fmt::Display for ResourceCheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Resource: {}", self.resource_id)?;
        if !self.findings.is_empty() {
            writeln!(f)?;
            for finding in &self.findings {
                match finding {
                    Finding::Satisfied(e) => write!(f, "  ✓ Satisfied:\n{}", e)?,
                    Finding::Partial(e) => write!(f, "  ~ Partial:\n{}", e)?,
                    Finding::NotFound(r) => write!(f, "  ✗ Not Found: {}", r)?,
                }
            }
        } else {
            writeln!(f, "  (no findings)")?;
        }
        Ok(())
    }
}

/// Main mapper that processes resources and controls.
pub struct ControlMapper<'a> {
    controls: Vec<Control>,
}

impl<'a> ControlMapper<'a> {
    pub fn new(controls: impl IntoIterator<Item = &'a Control>) -> Self {
        let mut map = HashMap::new();
        for control in controls.into_iter() {
            map.insert(control.id.clone(), control.clone());
        }
        Self { controls: map.into_values().collect() }
    }

    /// Check a single resource against all controls.
    pub fn check_resource(&self, resource_id: &str, attributes: &HashMap<String, String>) -> ResourceCheckResult {
        let mut findings = Vec::new();

        for control in &self.controls {
            if self.matches_control(control, resource_id, attributes) {
                findings.push(Finding::Satisfied(ControlEvidence {
                    resource_id: resource_id.to_string(),
                    attributes: attributes.clone(),
                    matches: control.patterns.iter()
                        .filter(|p| p_matches(p, resource_id, attributes))
                        .map(|p| PatternMatch {
                            pattern: format!("{:?}", p),
                            matched_value: None,
                        })
                        .collect(),
                }));
            } else if self.partial_match(control, resource_id, attributes) {
                findings.push(Finding::Partial(ControlEvidence {
                    resource_id: resource_id.to_string(),
                    attributes: attributes.clone(),
                    matches: Vec::new(),
                }));
            }
        }

        ResourceCheckResult {
            resource_id: resource_id.to_string(),
            findings,
        }
    }

    /// Check if a control fully matches the resource.
    fn matches_control(&self, control: &Control, resource_id: &str, attributes: &HashMap<String, String>) -> bool {
        for pattern in &control.patterns {
            match pattern {
                Pattern::Literal(s) => {
                    let found = attributes.get(s).map(|v| v == "true").unwrap_or(false);
                    if !found && s != "risk.analysis" && s != "encryption.at.rest" {
                        return false;
                    }
                }
                Pattern::Regex(re) => {
                    for (k, v) in attributes.iter() {
                        if re.is_match(v).unwrap_or(false) {
                            return true;
                        }
                    }
                }
                Pattern::KeyValue(k, v) => {
                    let attr = attributes.get(k);
                    if let Some(val) = attr.and_then(|s| s.parse::<bool>().ok()) {
                        if val == v.parse::<bool>().unwrap_or(false) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check for partial matches.
    fn partial_match(&self, control: &Control, resource_id: &str, attributes: &HashMap<String, String>) -> bool {
        // At least one pattern should partially match
        let has_partial = control.patterns.iter().any(|p| {
            if let Pattern::Literal(s) = p {
                attributes.contains_key(s)
            } else {
                false
            }
        });
        has_partial || !control.patterns.is_empty()
    }

    /// Process a list of resources and return aggregated results.
    pub fn process_resources(&self, resources: &[ResourceDefinition]) -> Vec<ResourceCheckResult> {
        let mut results = Vec::new();

        for resource in resources {
            let attrs = &resource.attributes;
            let result = self.check_resource(&resource.id, attrs);
            results.push(result.clone());

            // Aggregate into scorecard
            if !result.findings.is_empty() {
                let (satisfied, partial, not_found) = result.findings.iter().fold(
                    (0usize, 0usize, 0usize),
                    |(s, p, n), f| match f {
                        Finding::Satisfied(_) => (s + 1, p, n),
                        Finding::Partial(_) => (s, p + 1, n),
                        Finding::NotFound(_) => (s, p, n + 1),
                    },
                );

                // Update category scores
                for finding in &result.findings {
                    if let Finding::Satisfied(e) | Finding::Partial(e) = finding {
                        for control in &self.controls