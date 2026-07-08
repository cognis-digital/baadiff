//go:build ignore
// +build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ============================================================================
// HIPAA Control Definitions
// ============================================================================

const (
	HIPAAVersion = "2024.1"
	DefaultScoreThreshold = 85.0
)

type Control struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"` // Administrative, Physical, Technical, Organizational
	SubCategory string    `json:"sub_category"`
	Description string    `json:"description"`
	Required    bool      `json:"required"`
	Weight      float64   `json:"weight"`
	Priority    int       `json:"priority"` // 1 = Critical
}

type Finding struct {
	ControlID     string   `json:"control_id"`
	ControlName   string   `json:"control_name"`
	Status        Status   `json:"status"` // Present, Partial, Absent, Unknown
	Evidence      []string `json:"evidence,omitempty"`
	Gaps          []string  `json:"gaps,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
}

type Status int

const (
	StatusUnknown Status = iota
	StatusAbsent
	StatusPartial
	StatusPresent
)

func (s Status) String() string {
	switch s {
	case StatusUnknown:
		return "unknown"
	case StatusAbsent:
		return "absent"
	case StatusPartial:
		return "partial"
	case StatusPresent:
		return "present"
	default:
		return "unknown"
	}
}

type ScanResult struct {
	Metadata    Metadata      `json:"metadata"`
	Summary     Summary       `json:"summary"`
	Controls    []Finding     `json:"controls,omitempty"`
	CategoryBreakdown CategoryStats `json:"category_breakdown,omitempty"`
	RawEvidence  map[string][]string `json:"raw_evidence,omitempty"`
}

type Metadata struct {
	HIPAAVersion string   `json:"hipaa_version"`
	ToolName     string   `json:"tool_name"`
	TargetPath   string   `json:"target_path"`
	ScanTime     string   `json:"scan_time"`
	Version      string   `json:"version"`
}

type Summary struct {
	TotalControls    int       `json:"total_controls"`
	PresentCount     int       `json:"present_count"`
	PartialCount     int       `json:"partial_count"`
	AbsentCount      int       `json:"absent_count"`
	UnknownCount     int       `json:"unknown_count"`
	OverallScore     float64   `json:"overall_score"`
	PassThreshold    bool      `json:"pass_threshold"`
	CriticalGaps     []string  `json:"critical_gaps,omitempty"`
}

type CategoryStats struct {
	Category         string          `json:"category"`
	Total             int              `json:"total"`
	Present           int              `json:"present"`
	Partial           int              `json:"partial"`
	Absent            int              `json:"absent"`
	Unknown           int              `json:"unknown"`
	SubScore          float64          `json:"sub_score"`
}

// ============================================================================
// Control Mapper Core Types
// ============================================================================

type ConfigKey string

const (
	KeyVersion       ConfigKey = "version"
	KeyEncryption    ConfigKey = "encryption"
	KeyAccessControl ConfigKey = "access_control"
	KeyAudit         ConfigKey = "audit"
	KeyAuthenticationConfigKey = "authentication"
	KeyMFA           ConfigKey = "mfa"
	KeyIAM           ConfigKey = "iam"
	KeyNetwork       ConfigKey = "network"
	KeyVPC           ConfigKey = "vpc"
	KeySubnet        ConfigKey = "subnet"
	KeySecurityGroup ConfigKey = "security_group"
	KeyFirewall      ConfigKey = "firewall"
	KeyIAMRole       ConfigKey = "iam_role"
	KeyBucketPolicy  ConfigKey = "bucket_policy"
	KeyKMS           ConfigKey = "kms"
	KeyLogging       ConfigKey = "logging"
	KeyMonitoring    ConfigKey = "monitoring"
)

type ControlMapEntry struct {
	ControlID      string
	ControlName    string
	Category       string
	ConfigKeys     []ConfigKey
	Patterns       []*regexp.Regexp
	RequiredFields map[string]string
	Description    string
}

// ============================================================================
// Default HIPAA Control Definitions
// ============================================================================

var defaultControls = []Control{
	// Administrative Safeguards
	{
		ID:           "ADM-01",
		Name:         "Risk Analysis & Management",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Conduct initial and periodic risk analysis of ePHI",
		Required:     true,
		Weight:       10.0,
		Priority:     1,
	},
	{
		ID:           "ADM-02",
		Name:         "Risk Assessment Documentation",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Document risk analysis results and remediation plans",
		Required:     true,
		Weight:       8.0,
		Priority:     1,
	},
	{
		ID:           "ADM-03",
		Name:         "Security Management",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Assign security management responsibilities",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-04",
		Name:         "Security Official Designation",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Designate a security official or committee",
		Required:     true,
		Weight:       6.0,
		Priority:     2,
	},
	{
		ID:           "ADM-05",
		Name:         "Information System Activity Review",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Review information system activity regularly",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-06",
		Name:         "Security Incident Procedures",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Establish procedures for responding to security incidents",
		Required:     true,
		Weight:       9.0,
		Priority:     1,
	},
	{
		ID:           "ADM-07",
		Name:         "Contingency Plan",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Develop and test a contingency plan for system failure",
		Required:     true,
		Weight:       8.0,
		Priority:     1,
	},
	{
		ID:           "ADM-08",
		Name:         "Contingency Plan Testing & Updates",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Test and update contingency plan regularly",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-09",
		Name:         "Contingency Plan Communication & Training",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Communicate and train on contingency plan procedures",
		Required:     true,
		Weight:       6.0,
		Priority:     2,
	},
	{
		ID:           "ADM-10",
		Name:         "Contingency Plan Execution & Recovery Testing",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Execute and test recovery procedures periodically",
		Required:     true,
		Weight:       8.0,
		Priority:     1,
	},
	{
		ID:           "ADM-11",
		Name:         "Establishment of Procedures & Policies",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Establish procedures and policies for risk management",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-12",
		Name:         "Information System Activity Review (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Review information system activity regularly",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-13",
		Name:         "Security Incident Procedures (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Establish procedures for responding to security incidents",
		Required:     true,
		Weight:       9.0,
		Priority:     1,
	},
	{
		ID:           "ADM-14",
		Name:         "Contingency Plan (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Develop and test a contingency plan for system failure",
		Required:     true,
		Weight:       8.0,
		Priority:     1,
	},
	{
		ID:           "ADM-15",
		Name:         "Contingency Plan Testing & Updates (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Test and update contingency plan regularly",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-16",
		Name:         "Contingency Plan Communication & Training (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Communicate and train on contingency plan procedures",
		Required:     true,
		Weight:       6.0,
		Priority:     2,
	},
	{
		ID:           "ADM-17",
		Name:         "Contingency Plan Execution & Recovery Testing (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Execute and test recovery procedures periodically",
		Required:     true,
		Weight:       8.0,
		Priority:     1,
	},
	{
		ID:           "ADM-18",
		Name:         "Establishment of Procedures & Policies (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Establish procedures and policies for risk management",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-19",
		Name:         "Risk Analysis & Management (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Conduct initial and periodic risk analysis of ePHI",
		Required:     true,
		Weight:       10.0,
		Priority:     1,
	},
	{
		ID:           "ADM-20",
		Name:         "Risk Assessment Documentation (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Document risk analysis results and remediation plans",
		Required:     true,
		Weight:       8.0,
		Priority:     1,
	},
	{
		ID:           "ADM-21",
		Name:         "Security Management (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Assign security management responsibilities",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-22",
		Name:         "Security Official Designation (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Designate a security official or committee",
		Required:     true,
		Weight:       6.0,
		Priority:     2,
	},
	{
		ID:           "ADM-23",
		Name:         "Information System Activity Review (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Review information system activity regularly",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-24",
		Name:         "Security Incident Procedures (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Establish procedures for responding to security incidents",
		Required:     true,
		Weight:       9.0,
		Priority:     1,
	},
	{
		ID:           "ADM-25",
		Name:         "Contingency Plan (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Develop and test a contingency plan for system failure",
		Required:     true,
		Weight:       8.0,
		Priority:     1,
	},
	{
		ID:           "ADM-26",
		Name:         "Contingency Plan Testing & Updates (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Test and update contingency plan regularly",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-27",
		Name:         "Contingency Plan Communication & Training (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Communicate and train on contingency plan procedures",
		Required:     true,
		Weight:       6.0,
		Priority:     2,
	},
	{
		ID:           "ADM-28",
		Name:         "Contingency Plan Execution & Recovery Testing (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Execute and test recovery procedures periodically",
		Required:     true,
		Weight:       8.0,
		Priority:     1,
	},
	{
		ID:           "ADM-29",
		Name:         "Establishment of Procedures & Policies (Technical)",
		Category:     "Administrative",
		SubCategory:  "Risk Analysis",
		Description:  "Establish procedures and policies for risk management",
		Required:     true,
		Weight:       7.0,
		Priority:     2,
	},
	{
		ID:           "ADM-30",
		Name:         "Risk Analysis & Management (Technical)",
		Category:     "Administrative",