#!/usr/bin/env python3
"""
control_mapper.py - HIPAA Security Rule Control Mapper and Scoring Engine

A complete, self-contained module for scanning repositories and infrastructure
manifests to identify HIPAA Security Rule gaps and produce Business Associate
readiness scorecards.

Usage:
    python control_mapper.py <path> [--format terraform|k8s|aws] [--output report.md]
"""

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

DEFAULT_CONTROL_DEFINITIONS = """
controls:
  - id: ADM-101
    category: Administrative
    title: "Risk Analysis"
    description: "Conduct risk analysis to identify potential threats."
    keywords: ["risk", "analysis", "assessment", "threat"]
    weight: 25
    checkers:
      - type: keyword
        patterns: ["risk.*analysis", "threat.*assessment", "security.*review"]
      
  - id: ADM-102
    category: Administrative
    title: "Risk Management"
    description: "Implement risk management strategies."
    keywords: ["mitigate", "reduce", "accept", "transfer", "risk.*management"]
    weight: 25
    checkers:
      - type: keyword
        patterns: ["mitigation.*strategy", "risk.*treatment"]

  - id: PHY-101
    category: Physical
    title: "Facility Access Control"
    description: "Control physical access to facilities."
    keywords: ["access", "facility", "building", "perimeter"]
    weight: 20
    checkers:
      - type: keyword
        patterns: ["access.*control", "facility.*security", "perimeter.*fence"]

  - id: PHY-102
    category: Physical
    title: "Workstation Security"
    description: "Secure workstation access and use."
    keywords: ["workstation", "laptop", "mobile.*device"]
    weight: 20
    checkers:
      - type: keyword
        patterns: ["workstation.*security", "laptop.*policy"]

  - id: TECH-101
    category: Technical
    title: "Access Control"
    description: "Implement unique user identification and access control."
    keywords: ["access.*control", "authentication", "authorization"]
    weight: 25
    checkers:
      - type: keyword
        patterns: ["unique.*user.*id", "mfa", "two-factor", "sso"]

  - id: TECH-102
    category: Technical
    title: "Authentication"
    description: "Implement strong authentication mechanisms."
    keywords: ["password", "credential", "token", "certificate"]
    weight: 25
    checkers:
      - type: keyword
        patterns: ["strong.*password", "mfa", "biometric"]

  - id: ORG-101
    category: Organizational
    title: "Business Associate Agreement"
    description: "Execute BAAs with business associates."
    keywords: ["baa", "business.*associate", "contractor"]
    weight: 25
    checkers:
      - type: keyword
        patterns: ["business.*associate.*agreement", "subprocessor.*list"]

  - id: ORG-102
    category: Organizational
    title: "Security Incident Procedures"
    description: "Establish procedures for security incidents."
    keywords: ["incident", "response", "procedure"]
    weight: 25
    checkers:
      - type: keyword
        patterns: ["incident.*response.*plan", "disaster.*recovery"]

total_weight: 100
"""


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class ControlCategory(Enum):
    """HIPAA Security Rule categories."""
    
    ADMINISTRATIVE = "Administrative"
    PHYSICAL = "Physical"
    TECHNICAL = "Technical"
    ORGANIZATIONAL = "Organizational"


@dataclass(frozen=True)
class Checker:
    """A pattern checker for control validation."""
    
    type: str  # 'keyword', 'regex', 'yaml_field', 'terraform_attr'
    patterns: List[str] = field(default_factory=list)
    terraform_attrs: List[str] = field(default_factory=list)
    yaml_fields: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ControlDefinition:
    """Defines a single HIPAA control."""
    
    id: str
    category: ControlCategory
    title: str
    description: str
    keywords: List[str]
    weight: int
    checkers: List[Checker] = field(default_factory=list)


@dataclass
class CheckResult:
    """Result of checking a single control."""
    
    control_id: str
    category: ControlCategory
    title: str
    found: bool
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.5
    issues: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete result of scanning a repository."""
    
    controls: Dict[str, CheckResult]
    total_weight: int
    achieved_weight: int
    score: float
    timestamp: datetime
    
    @property
    def percentage(self) -> float:
        return (self.achieved_weight / self.total_weight * 100) if self.total_weight > 0 else 0.0


# =============================================================================
# PARSER REGISTRY
# =============================================================================

class ParserRegistry:
    """Registry for file format parsers."""
    
    _parsers: Dict[str, Callable] = {}
    
    @classmethod
    def register(cls, name: str) -> Callable:
        """Decorator to register a parser."""
        def decorator(func: Callable):
            cls._parsers[name] = func
            return func
        return decorator
    
    @classmethod
    def get_parser(cls, format_name: str) -> Optional[Callable]:
        """Get parser for specified format."""
        return cls._parsers.get(format_name.lower())


# =============================================================================
# FILE PARSERS
# =============================================================================

@ParserRegistry.register("terraform")
def parse_terraform(content: str) -> Dict[str, Any]:
    """Parse Terraform HCL content and extract relevant attributes."""
    
    result = {
        "format": "terraform",
        "resources": [],
        "variables": {},
        "providers": set(),
        "modules": []
    }
    
    # Extract resource blocks
    resource_pattern = r'resource\s+"([^"]+)"\s+\{([^}]*)\}'
    for match in re.finditer(resource_pattern, content):
        resource_name = match.group(1)
        resource_body = match.group(2)
        
        resource_info = {
            "name": resource_name,
            "body": resource_body[:500]  # Truncate for readability
        }
        result["resources"].append(resource_info)
    
    # Extract variable definitions
    var_pattern = r'variable\s+"([^"]+)"\s+\{[^}]*type\s*=\s*"([^"]*)"'
    for match in re.finditer(var_pattern, content):
        var_name = match.group(1)
        var_type = match.group(2)
        result["variables"][var_name] = var_type
    
    # Extract provider blocks
    provider_pattern = r'provider\s+"([^"]+)"\s+\{[^}]*\}'
    for match in re.finditer(provider_pattern, content):
        provider_name = match.group(1)
        result["providers"].add(provider_name)
    
    return result


@ParserRegistry.register("k8s")
def parse_kubernetes(content: str) -> Dict[str, Any]:
    """Parse Kubernetes YAML manifests."""
    
    result = {
        "format": "kubernetes",
        "namespaces": set(),
        "resources": [],
        "deployments": 0,
        "services": 0,
        "pods": 0
    }
    
    # Extract namespace from metadata
    ns_pattern = r'metadata:\s*[^}]*namespace:\s*"([^"]*)"'
    for match in re.finditer(ns_pattern, content):
        result["namespaces"].add(match.group(1))
    
    # Count resource types
    deployment_count = len(re.findall(r'apiVersion: apps/v1.*kind: Deployment', content))
    service_count = len(re.findall(r'apiVersion: v1.*kind: Service', content))
    pod_count = len(re.findall(r'apiVersion: v1.*kind: Pod', content))
    
    result["deployments"] = deployment_count
    result["services"] = service_count
    result["pods"] = pod_count
    
    return result


@ParserRegistry.register("aws")
def parse_aws_cloudformation(content: str) -> Dict[str, Any]:
    """Parse AWS CloudFormation templates."""
    
    result = {
        "format": "cloudformation",
        "resources": [],
        "parameters": {},
        "outputs": {}
    }
    
    # Extract resource types
    resource_pattern = r'"Type"\s*:\s*"([^"]+)"'
    for match in re.finditer(resource_pattern, content):
        result["resources"].append(match.group(1))
    
    # Extract parameters
    param_pattern = r'"Parameters"\s*:\s*\{[^}]*"([^"]+)":\s*"([^"]*)"'
    for match in re.finditer(param_pattern, content):
        result["parameters"][match.group(1)] = match.group(2)
    
    # Extract outputs
    output_pattern = r'"Outputs"\s*:\s*\{[^}]*"([^"]+)":\s*"([^"]*)"'
    for match in re.finditer(output_pattern, content):
        result["outputs"][match.group(1)] = match.group(2)
    
    return result


@ParserRegistry.register("generic")
def parse_generic(content: str) -> Dict[str, Any]:
    """Generic parser that looks for HIPAA-related keywords."""
    
    result = {
        "format": "generic",
        "content_length": len(content),
        "hipaa_keywords_found": [],
        "lines_analyzed": 0
    }
    
    # Look for common HIPAA/security keywords
    security_patterns = [
        r'password\s*:',
        r'mfa|two-factor',
        r'ssl|tls|https',
        r'encryption',
        r'certificate',
        r'authentication',
        r'authorization',
        r'access.*control',
        r'audit.*log',
        r'backup',
        r'redundancy',
        r'disaster.*recovery',
        r'incident.*response'
    ]
    
    for pattern in security_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            result["hipaa_keywords_found"].append(pattern)
    
    return result


# =============================================================================
# CONTROL CHECKER ENGINE
# =============================================================================

class ControlChecker:
    """Engine to check controls against parsed content."""
    
    def __init__(self, control_definitions: List[ControlDefinition] = None):
        self.controls = []
        if control_definitions:
            self.controls.extend(control_definitions)
    
    def add_control(self, control: ControlDefinition) -> None:
        """Add a control definition."""
        self.controls.append(control)
    
    def check_all(self, parsed_data: Dict[str, Any]) -> List[CheckResult]:
        """Check all controls against the parsed data."""
        results = []
        
        for control in self.controls:
            result = CheckResult(
                control_id=control.id,
                category=control.category,
                title=control.title,
                found=False,
                confidence=0.5
            )
            
            # Check each checker type
            for checker in control.checkers:
                evidence = self._run_checker(checker, parsed_data)
                
                if evidence:
                    result.found = True
                    result.evidence.extend(evidence)
                    result.confidence = min(result.confidence + 0.15, 1.0)
            
            # If no evidence found but keywords match, give partial credit
            keyword_matches = self._check_keywords(control.keywords, parsed_data.get("content", ""))
            if keyword_matches:
                result.found = True
                result.evidence.extend(keyword_matches)
                result.confidence = min(result.confidence + 0.1, 1.0)
            
            results.append(result)
        
        return results
    
    def _run_checker(self, checker: Checker, parsed_data: Dict[str, Any]) -> List[str]:
        """Run a single checker and return evidence if found."""
        evidence = []
        
        if checker.type == "keyword":
            content = self._extract_content(parsed_data)
            for pattern in checker.patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    evidence.append(f"Pattern '{pattern}' matched: {matches[:2]}")
        
        elif checker.type == "terraform_attr":
            resources = parsed_data.get("resources", [])
            for attr in checker.terraform_attrs:
                found = any(attr.lower() in r.get("name", "").lower() 
                          or attr.lower() in r.get("body", "").lower() 
                          for r in resources)
                if found:
                    evidence.append(f"Found attribute '{attr}'")
        
        elif checker.type == "yaml_field":
            content = parsed_data.get("content", "")
            for field_path in checker.yaml_fields:
                if field_path.lower() in content.lower():
                    evidence.append(f"Found YAML field path: {field_path}")
        
        return evidence
    
    def _check_keywords(self, keywords: List[str], content: str) -> List[str]:
        """Check if any control keywords are present in the content."""
        matches = []
        for keyword in keywords:
            if re.search(keyword, content, re.IGNORECASE):
                matches.append(f"Keyword '{keyword}' found")
        return matches
    
    def _extract_content(self, parsed_data: Dict[str, Any]) -> str:
        """Extract text content from parsed data."""
        # Try to get raw content first
        if "content" in parsed_data:
            return parsed_data["content"]
        
        # Fallback: join all resource bodies
        resources = parsed_data.get("resources", [])
        if resources:
            return "\n".join(r.get("body", "") for r in resources)
        
        # Last resort: use generic content
        return str(parsed_data).replace("\n", " ")


# =============================================================================
# SCORING ENGINE
# =============================================================================

class ScoreCalculator:
    """Calculates Business Associate readiness scores."""
    
    def __init__(self, total_weight: int = 100):
        self.total_weight = total_weight
    
    def calculate_score(self, results: List[CheckResult]) -> Tuple[float, float]:
        """Calculate weighted score and pass/fail status."""
        
        achieved_weight = sum(
            r.confidence * result.weight 
            for result in results 
            if result.found
        )
        
        # Normalize by total weight (assuming 1.0 confidence per control)
        max_achieved = sum(result.weight for result in results)
        normalized_score = achieved_weight / max_achieved if max_achieved > 0 else 0
        
        return normalized_score, achieved_weight
    
    def get_grade(self, score: float) -> str:
        """Convert numeric score to letter grade."""
        if score >= 0.95:
            return "A"
        elif score >= 0.85:
            return "B"
        elif score >= 0.70:
            return "C"
        elif score >= 0.50:
            return "D"
        else:
            return "F"


# =============================================================================
# REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    """Generates various report formats."""
    
    def __init__(self, calculator: ScoreCalculator = None):
        self.calculator = calculator or ScoreCalculator()
    
    def generate_markdown(self, scan_result: Scan