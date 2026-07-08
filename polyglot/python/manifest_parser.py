"""
polyglot/python/manifest_parser.py

HIPAA Security Rule Gap Scanner & Business Associate Readiness Scorecard Generator

Parses Terraform, CloudFormation, and Kubernetes manifests to identify security gaps
and produce a comprehensive compliance scorecard for Business Associate Agreement (BAA) readiness.
"""

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterator


class ControlCategory(Enum):
    """HIPAA Security Rule categories."""
    ACCESS_CONTROL = "Access Control"
    AUDIT_CONTROLS = "Audit Controls"
    AVAILABILITY = "Availability"
    INTEGRITY = "Data Integrity"
    PERSONNEL = "Personnel Training & Management"
    PHYSICAL = "Physical Environment"
    RISK_ANALYSIS = "Risk Analysis"
    TRANSMISSION = "Transmission Security"


class ControlStatus(Enum):
    """Compliance status for each control."""
    COMPLIANT = auto()  # Explicitly meets requirement
    PARTIAL = auto()   # Partial implementation or gaps exist
    NON_COMPLIANT = auto()  # Missing or clearly non-compliant
    UNKNOWN = auto()     # Insufficient data to determine


@dataclass
class ControlDefinition:
    """Represents a single HIPAA control."""
    id: str
    category: ControlCategory
    title: str
    description: str
    weight: float  # Impact on overall score (0.0-1.0)
    
    def __hash__(self):
        return hash(self.id)


# Define core HIPAA Security Rule controls with weights
CONTROLS = {
    "AC-1": ControlDefinition(
        id="AC-1", category=ControlCategory.ACCESS_CONTROL,
        title="Access Control Policy and Procedures",
        description="Organization must establish policies governing access to ePHI.",
        weight=0.12
    ),
    "AC-2": ControlDefinition(
        id="AC-2", category=ControlCategory.ACCESS_CONTROL,
        title="Account Management",
        description="Unique user identification and authentication for ePHI systems.",
        weight=0.15
    ),
    "AC-3": ControlDefinition(
        id="AC-3", category=ControlCategory.ACCESS_CONTROL,
        title="Access Enforcement",
        description="Enforce least privilege access to ePHI resources.",
        weight=0.14
    ),
    "AU-2": ControlDefinition(
        id="AU-2", category=ControlCategory.AUDIT_CONTROLS,
        title="Audit Trail Policy and Procedures",
        description="Establish policies for audit logging of ePHI access.",
        weight=0.10
    ),
    "AU-3": ControlDefinition(
        id="AU-3", category=ControlCategory.AUDIT_CONTROLS,
        title="Content of Audit Records",
        description="Capture who accessed ePHI and when (user ID, timestamp).",
        weight=0.12
    ),
    "CM-1": ControlDefinition(
        id="CM-1", category=ControlCategory.AVAILABILITY,
        title="Configuration Management Policy",
        description="Policies for managing configuration of ePHI systems.",
        weight=0.08
    ),
    "CM-2": ControlDefinition(
        id="CM-2", category=ControlCategory.AVAILABILITY,
        title="Baseline Configuration",
        description="Establish and maintain secure baselines for ePHI systems.",
        weight=0.13
    ),
    "IA-2": ControlDefinition(
        id="IA-2", category=ControlCategory.ACCESS_CONTROL,
        title="Identification and Authentication (Network)",
        description="Mutual authentication between network entities handling ePHI.",
        weight=0.16
    ),
    "IA-3": ControlDefinition(
        id="IA-3", category=ControlCategory.ACCESS_CONTROL,
        title="Network Identity Federation",
        description="Federated identity management for cross-system access.",
        weight=0.09
    ),
    "IA-4": ControlDefinition(
        id="IA-4", category=ControlCategory.ACCESS_CONTROL,
        title="Encrypted Transmission of Credentials",
        description="Encrypt credentials during transmission between systems.",
        weight=0.11
    ),
    "PE-2": ControlDefinition(
        id="PE-2", category=ControlCategory.PHYSICAL,
        title="Physical Environment Perimeter Security",
        description="Secure physical perimeter for on-premises ePHI systems.",
        weight=0.08
    ),
    "PE-3": ControlDefinition(
        id="PE-3", category=ControlCategory.PHYSICAL,
        title="Workstation and Mobile Device Security",
        description="Secure workstations accessing ePHI (lock screens, encryption).",
        weight=0.10
    ),
    "SC-2": ControlDefinition(
        id="SC-2", category=ControlCategory.INTEGRITY,
        title="Configuration Change Management",
        description="Change management for systems handling ePHI.",
        weight=0.11
    ),
    "SC-3": ControlDefinition(
        id="SC-3", category=ControlCategory.AVAILABILITY,
        title="Connection Limitation and Data Center Redundancy",
        description="Redundant systems for ePHI availability.",
        weight=0.14
    ),
    "SC-8": ControlDefinition(
        id="SC-8", category=ControlCategory.AVAILABILITY,
        title="Transmission Confidentiality and Integrity",
        description="Encrypt data in transit (TLS 1.2+).",
        weight=0.15
    ),
    "SC-13": ControlDefinition(
        id="SC-13", category=ControlCategory.ACCESS_CONTROL,
        title="Secure Wireless Access",
        description="Secure wireless networks for ePHI access.",
        weight=0.07
    ),
}


@dataclass
class ResourceScanResult:
    """Results for a single parsed resource."""
    provider: str
    name: str
    type_: str
    tags: Dict[str, Any] = field(default_factory=dict)
    attributes: Dict[str, Any] = field(default_factory=dict)
    controls_applied: List[ControlDefinition] = field(default_factory=list)
    control_scores: Dict[str, ControlStatus] = field(default_factory=dict)


@dataclass 
class ScanSummary:
    """Aggregated results from a full scan."""
    total_resources: int = 0
    resources_with_ephi: int = 0
    overall_score: float = 1.0
    category_scores: Dict[ControlCategory, Tuple[float, List[str]]] = field(default_factory=dict)
    resource_results: List[ResourceScanResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)


def normalize_resource_name(name: str) -> str:
    """Normalize resource names for consistent matching."""
    if not name:
        return "unknown"
    # Remove common prefixes and separators
    normalized = re.sub(r'^(aws_|azure_|gcp_)?(module|resource)_?', '', name, flags=re.IGNORECASE)
    return normalized.strip().lower()


def extract_ephi_indicators(resource: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract indicators that suggest ePHI is handled by this resource."""
    indicators = []
    
    # Check common tags/labels for ePHI keywords
    ephi_keywords = ['ephi', 'hipaa', 'healthcare', 'patient', 'clinical', 
                     'medical', 'icd10', 'cda', 'fhir', 'hl7']
    
    all_strings = []
    if isinstance(resource, dict):
        for key in resource:
            val = resource[key]
            if isinstance(val, str):
                all_strings.append(val)
            elif isinstance(val, list):
                all_strings.extend(str(v) for v in val)
    
    found_keywords = []
    for keyword in ephi_keywords:
        pattern = re.compile(rf'\b{keyword}\b', re.IGNORECASE)
        matches = [m.group(0) for m in pattern.finditer(' '.join(all_strings)) if m]
        if matches:
            found_keywords.extend(matches[:3])  # Limit to avoid duplicates
    
    if found_keywords:
        indicators.append({
            'type': 'keyword_match',
            'keywords': list(set(found_keywords)),
            'confidence': 0.85,
            'evidence': f"Found ePHI-related keywords in resource attributes"
        })
    
    # Check for common ePHI system patterns
    system_patterns = [
        (r'^(aws|azure|gcp)_health', 'Healthcare cloud provider'),
        (r'^patient_|^clinical_', 'Patient/clinical prefix'),
        (r'^(ephi|hipaa|health)', 'Explicit HIPAA tag'),
    ]
    
    for pattern, description in system_patterns:
        if re.search(pattern, ' '.join(all_strings), re.IGNORECASE):
            indicators.append({
                'type': 'system_pattern',
                'pattern': pattern,
                'description': description,
                'confidence': 0.75
            })
    
    return indicators


def evaluate_control(resource: Dict[str, Any], control_id: str) -> Tuple[ControlStatus, float]:
    """Evaluate a single control against resource attributes."""
    score = 1.0
    status = ControlStatus.COMPLIANT
    
    # Placeholder evaluation logic - would be expanded with real rules
    if 'tags' in resource:
        tags_lower = {k.lower(): v for k, v in resource['tags'].items()}
        
        # Check for negative indicators
        negative_tags = ['dev', 'test', 'temp', 'staging']
        for tag in negative_tags:
            if tag in tags_lower:
                score -= 0.15
        
        # Check for positive indicators
        positive_tags = ['prod', 'secure', 'encrypted', 'tls']
        for tag in positive_tags:
            if tag in tags_lower:
                score += 0.05
    
    return (status, max(0.0, min(1.0, score)))


def parse_terraform_manifest(manifest_path: str) -> Iterator[Dict[str, Any]]:
    """Parse a Terraform manifest file."""
    with open(manifest_path, 'r') as f:
        content = f.read()
    
    # Extract resource blocks using regex
    pattern = r'resource\s+"([^"]+)"\s*{\s*\n(.*?)\n\s*}'
    matches = re.findall(pattern, content, re.DOTALL)
    
    for match in matches:
        name, body = match
        
        # Parse resource attributes
        resource = {
            'provider': name.split('.')[0] if '.' in name else name,
            'name': name,
            'type_': name,
            'body': body,
        }
        
        # Extract tags from the body
        tag_pattern = r'tags\s*=\s*\{([^}]+)\}'
        tags_match = re.search(tag_pattern, body)
        if tags_match:
            tags_str = tags_match.group(1)
            resource['tags'] = parse_terraform_tags(tags_str)
        
        # Extract common attributes
        attr_patterns = [
            (r'(?P<name>\w+)\s*=\s*"?(?P<value>[^"]*)"', 'attribute'),
            (r'(?P<name>\w+)\s*=\s*\{([^}]+)\}', 'nested_block'),
        ]
        
        for pattern, attr_type in attr_patterns:
            matches = re.findall(pattern, body)
            if matches:
                resource[attr_type] = matches
        
        yield resource


def parse_terraform_tags(tags_str: str) -> Dict[str, Any]:
    """Parse Terraform tags into a structured dictionary."""
    result = {}
    
    # Handle various tag formats
    patterns = [
        (r'"([^"]+)"\s*=\s*"([^"]*)"', lambda m: {'key': m.group(1), 'value': m.group(2)}),
        (r"'([^']+)'\s*=\s*'([^']*)'", lambda m: {'key': m.group(1), 'value': m.group(2)}),
    ]
    
    for pattern, parser in patterns:
        matches = re.findall(pattern, tags_str)
        for match in matches:
            parsed = parser(match) if len(match) == 2 else {'key': match[0], 'value': ''}
            result[parsed['key'].lower()] = parsed.get('value', '')
    
    return result


def parse_cloudformation_manifest(manifest_path: str) -> Iterator[Dict[str, Any]]:
    """Parse a CloudFormation manifest file."""
    with open(manifest_path, 'r') as f:
        content = f.read()
    
    # Extract resources from the template
    pattern = r'Resources:\s*\n((?:[^{}]|(?:\{[^{}]*\}))*?)\n\s*Outputs:'
    match = re.search(pattern, content, re.DOTALL)
    
    if not match:
        return
    
    resources_str = match.group(1)
    
    # Parse individual resource definitions
    resource_pattern = r'(\w+)\s*:\s*\{([^}]+)\}'
    for full_match in re.finditer(resource_pattern, resources_str):
        name, body = full_match.groups()
        
        resource = {
            'provider': 'cloudformation',
            'name': name,
            'type_': name,
            'body': body,
        }
        
        # Extract type (e.g., AWS::S3::Bucket)
        type_match = re.search(r'type\s*:\s*"([^"]+)"', body)
        if type_match:
            resource['type_'] = type_match.group(1).split('::')[0]
        
        # Extract tags
        tag_pattern = r'Tags\s*=\s*\[\s*(.*?)\]'
        tags_match = re.search(tag_pattern, body, re.DOTALL)
        if tags_match:
            resource['tags'] = parse_cf_tags(tags_match.group(1))
        
        yield resource


def parse_cf_tags(tags_str: str) -> Dict[str, Any]:
    """Parse CloudFormation Tags."""
    result = {}
    
    # Handle various formats
    patterns = [
        (r'"([^"]+)"\s*:\s*"([^"]*)"', lambda m: {'key': m.group(1), 'value': m.group(2)}),
    ]
    
    for pattern, parser in patterns:
        matches = re.findall(pattern, tags_str)
        for match in matches:
            parsed = parser(match) if len(match) == 2 else {'key': match[0], 'value': ''}
            result[parsed['key'].lower()] = parsed.get('value', '')
    
    return result


def parse_kubernetes_manifest(manifest_path: str) -> Iterator[Dict[str, Any]]:
    """Parse a Kubernetes manifest file."""
    with open(manifest_path, 'r') as f:
        content = f.read()
    
    # Extract Kind and Name from each resource
    pattern = r'kind:\s*([^:]+)\n\s+metadata:\n\s+name:\s*"([^"]*)"'
    matches = re.findall(pattern, content)
    
    for kind, name in matches:
        resource = {
            'provider': 'kubernetes',
            'name': name,
            'type_': kind.lower(),
            'body': '',  # Would need more complex parsing to extract full spec
        }
        
        # Check for namespace (often indicates production vs dev)
        ns_match = re.search(r'namespace:\s*"([^"]*)"', content)
        if ns_match:
            resource['tags']['namespace'] = ns_match.group(1).lower()
        
        yield resource


def scan_manifest(manifest_path: str, format_hint: Optional[str] = None) -> ScanSummary:
    """Scan a manifest file and produce results."""
    summary = ScanSummary()
    
    # Determine parser based on hint or auto-detection
    if format_hint == 'terraform':
        resources = parse_terraform_manifest(manifest_path)
    elif format_hint == 'cloudformation':
        resources = parse_cloudformation_manifest(manifest_path)
    elif format_hint == 'kubernetes':
        resources = parse_kubernetes_manifest(manifest_path)
    else:
        # Auto-detect based on file content
        with open(manifest_path, 'r') as f:
            content = f.read()
        
        if 'resource "' in content or 'resource "' in content:
            format_hint = 'terraform'
            resources = parse_terraform_manifest(manifest_path)
        elif 'Resources:' in content and '::' in content:
            format_hint = 'cloudformation'
            resources = parse_cloudformation_manifest(manifest_path)
        elif 'kind:' in content:
            format_hint = 'kubernetes'
            resources = parse_kubernetes_manifest(manifest_path)
        else:
            # Default to terraform as most common
            format_hint = 'terraform'
            resources = parse_terraform_manifest(manifest_path)
    
    summary.total_resources = len(list(resources))
    
    # Process each resource
    for resource in resources:
        result = ResourceScanResult(
            provider=resource.get('provider', 'unknown'),
            name=resource.get('name', 'unknown'),
            type_=resource.get('type_',